/* SPDX-License-Identifier: GPL-2.0-only */

#include <arch/exception.h>
#include <assert.h>
#include <console/console.h>
#include <bootmode.h>
#include <fmap.h>
#include <security/tpm/tspi/crtm.h>
#include <security/tpm/tss/vendor/cr50/cr50.h>
#include <security/vboot/misc.h>
#include <security/vboot/vbnv.h>
#include <security/vboot/tpm_common.h>
#include <string.h>
#include <timestamp.h>
#include <vb2_api.h>
#include <boot_device.h>
#include <pc80/mc146818rtc.h>

#include "antirollback.h"

/* The max hash size to expect is for SHA512. */
#define VBOOT_MAX_HASH_SIZE VB2_SHA512_DIGEST_SIZE

/* exports */

vb2_error_t vb2ex_read_resource(struct vb2_context *ctx,
				enum vb2_resource_index index,
				uint32_t offset,
				void *buf,
				uint32_t size)
{
	struct region_device rdev;
	const char *name;

	switch (index) {
	case VB2_RES_GBB:
		name = "GBB";
		break;
	case VB2_RES_FW_VBLOCK:
		if (vboot_is_firmware_slot_a(ctx))
			name = "VBLOCK_A";
		else
			name = "VBLOCK_B";
		break;
	default:
		return VB2_ERROR_EX_READ_RESOURCE_INDEX;
	}

	if (fmap_locate_area_as_rdev(name, &rdev))
		return VB2_ERROR_EX_READ_RESOURCE_SIZE;

	if (rdev_readat(&rdev, buf, offset, size) != size)
		return VB2_ERROR_EX_READ_RESOURCE_SIZE;

	return VB2_SUCCESS;
}

static vb2_error_t handle_digest_result(void *slot_hash, size_t slot_hash_sz)
{
	int is_resume;

	/*
	 * Chrome EC is the only support for vboot_save_hash() &
	 * vboot_retrieve_hash(), if Chrome EC is not enabled then return.
	 */
	if (!CONFIG(EC_GOOGLE_CHROMEEC))
		return VB2_SUCCESS;

	/*
	 * Nothing to do since resuming on the platform doesn't require
	 * vboot verification again.
	 */
	if (!CONFIG(RESUME_PATH_SAME_AS_BOOT))
		return VB2_SUCCESS;

	/*
	 * Assume that if vboot doesn't start in bootblock verified
	 * RW memory init code is not employed. i.e. memory init code
	 * lives in RO CBFS.
	 */
	if (!CONFIG(VBOOT_STARTS_IN_BOOTBLOCK))
		return VB2_SUCCESS;

	is_resume = platform_is_resuming();

	if (is_resume > 0) {
		uint8_t saved_hash[VBOOT_MAX_HASH_SIZE];
		const size_t saved_hash_sz = sizeof(saved_hash);

		assert(slot_hash_sz <= saved_hash_sz);

		printk(BIOS_DEBUG, "Platform is resuming.\n");

		if (vboot_retrieve_hash(saved_hash, saved_hash_sz)) {
			printk(BIOS_ERR, "Couldn't retrieve saved hash.\n");
			return VB2_ERROR_UNKNOWN;
		}

		if (memcmp(saved_hash, slot_hash, slot_hash_sz)) {
			printk(BIOS_ERR, "Hash mismatch on resume.\n");
			return VB2_ERROR_UNKNOWN;
		}
	} else if (is_resume < 0)
		printk(BIOS_ERR, "Unable to determine if platform resuming.\n");

	printk(BIOS_DEBUG, "Saving vboot hash.\n");

	/* Always save the hash for the current boot. */
	if (vboot_save_hash(slot_hash, slot_hash_sz)) {
		printk(BIOS_ERR, "Error saving vboot hash.\n");
		/* Though this is an error don't report it up since it could
		 * lead to a reboot loop. The consequence of this is that
		 * we will most likely fail resuming because of EC issues or
		 * the hash digest not matching. */
		return VB2_SUCCESS;
	}

	return VB2_SUCCESS;
}

static vb2_error_t hash_body(struct vb2_context *ctx,
			     struct region_device *fw_body)
{
	uint64_t load_ts;
	uint32_t remaining;
	uint8_t block[CONFIG_VBOOT_HASH_BLOCK_SIZE];
	uint8_t hash_digest[VBOOT_MAX_HASH_SIZE];
	const size_t hash_digest_sz = sizeof(hash_digest);
	size_t block_size = sizeof(block);
	size_t offset;
	vb2_error_t rv;

	/* Clear the full digest so that any hash digests less than the
	 * max have trailing zeros. */
	memset(hash_digest, 0, hash_digest_sz);

	/*
	 * Since loading the firmware and calculating its hash is intertwined,
	 * we use this little trick to measure them separately and pretend it
	 * was first loaded and then hashed in one piece with the timestamps.
	 * (This split won't make sense with memory-mapped media like on x86.)
	 */
	load_ts = timestamp_get();
	timestamp_add(TS_HASH_BODY_START, load_ts);

	remaining = region_device_sz(fw_body);
	offset = 0;

	/* Start the body hash */
	rv = vb2api_init_hash(ctx, VB2_HASH_TAG_FW_BODY);
	if (rv)
		return rv;

	/* Extend over the body */
	while (remaining) {
		uint64_t temp_ts;
		if (block_size > remaining)
			block_size = remaining;

		temp_ts = timestamp_get();
		if (rdev_readat(fw_body, block, offset, block_size) < 0)
			return VB2_ERROR_UNKNOWN;
		load_ts += timestamp_get() - temp_ts;

		rv = vb2api_extend_hash(ctx, block, block_size);
		if (rv)
			return rv;

		remaining -= block_size;
		offset += block_size;
	}

	timestamp_add(TS_LOADING_END, load_ts);
	timestamp_add_now(TS_HASHING_END);

	/* Check the result (with RSA signature verification) */
	rv = vb2api_check_hash_get_digest(ctx, hash_digest, hash_digest_sz);
	if (rv)
		return rv;

	timestamp_add_now(TS_HASH_BODY_END);

	return handle_digest_result(hash_digest, hash_digest_sz);
}

static uint32_t extend_pcrs(struct vb2_context *ctx)
{
	return vboot_extend_pcr(ctx, CONFIG_PCR_BOOT_MODE, BOOT_MODE_PCR) ||
		   vboot_extend_pcr(ctx, CONFIG_PCR_HWID, HWID_DIGEST_PCR);
}

#define EC_EFS_BOOT_MODE_VERIFIED_RW	0x00
#define EC_EFS_BOOT_MODE_UNTRUSTED_RO	0x01
#define EC_EFS_BOOT_MODE_TRUSTED_RO	0x02

static const char *get_boot_mode_string(uint8_t boot_mode)
{
	if (boot_mode == EC_EFS_BOOT_MODE_TRUSTED_RO)
		return "TRUSTED_RO";
	else if (boot_mode == EC_EFS_BOOT_MODE_UNTRUSTED_RO)
		return "UNTRUSTED_RO";
	else if (boot_mode == EC_EFS_BOOT_MODE_VERIFIED_RW)
		return "VERIFIED_RW";
	else
		return "UNDEFINED";
}

static void check_boot_mode(struct vb2_context *ctx)
{
	uint8_t boot_mode;
	int rv;

	rv = tlcl_cr50_get_boot_mode(&boot_mode);
	switch (rv) {
	case TPM_E_NO_SUCH_COMMAND:
		printk(BIOS_WARNING, "GSC does not support GET_BOOT_MODE.\n");
		/* Proceed to legacy boot model. */
		return;
	case TPM_SUCCESS:
		break;
	default:
		printk(BIOS_ERR,
		       "Communication error in getting GSC boot mode.\n");
		vb2api_fail(ctx, VB2_RECOVERY_GSC_BOOT_MODE, rv);
		return;
	}

	printk(BIOS_INFO, "GSC says boot_mode is %s(0x%02x).\n",
	       get_boot_mode_string(boot_mode), boot_mode);

	if (boot_mode == EC_EFS_BOOT_MODE_UNTRUSTED_RO)
		ctx->flags |= VB2_CONTEXT_NO_BOOT;
	else if (boot_mode == EC_EFS_BOOT_MODE_TRUSTED_RO)
		ctx->flags |= VB2_CONTEXT_EC_TRUSTED;
}

#define RECOVERY_OVERRIDE_ADDR 0xf7

static bool use_vboot(bool is_s3)
{
#if CONFIG(VBOOT_HYBRID)
	uint8_t recovery_override = cmos_read(RECOVERY_OVERRIDE_ADDR);
	int counter = recovery_override & 0xf;

	printk(BIOS_INFO, "recovery_override=0x%x, is_s3=%d\n", recovery_override, is_s3);

	if ((recovery_override & 0xf0) != 0xc0)
		return 0;

	if (is_s3)
		return 1;

	if (counter == 0) {
		cmos_write(0xff, RECOVERY_OVERRIDE_ADDR);
		return 0;
	}

	if (counter != 0xf)
		cmos_write(0xc0 | (counter - 1), RECOVERY_OVERRIDE_ADDR);
#endif

	return 1;
}

static bool ensure_tpm_rw_is_locked(bool is_s3)
{
	static const uint8_t boot_mode_digest[VB2_PCR_DIGEST_RECOMMENDED_SIZE] = {
		/* sha256("skipmode") */
		0x73, 0x17, 0x91, 0x09, 0x91, 0x2a, 0xbd, 0xcc,
		0x23, 0xad, 0x82, 0x2c, 0x2f, 0xd5, 0x81, 0xad,
		0xc5, 0xa6, 0xef, 0xc2, 0xae, 0x73, 0xfd, 0xb3,
		0x7b, 0x56, 0xb7, 0x14, 0xbd, 0xb9, 0x82, 0x99,
	};
	static const uint8_t hwid_unknown_digest[VB2_PCR_DIGEST_RECOMMENDED_SIZE] = {
		/* sha256("unknown") */
		0xb2, 0x3a, 0x6a, 0x84, 0x39, 0xc0, 0xdd, 0xe5,
		0x51, 0x58, 0x93, 0xe7, 0xc9, 0x0c, 0x1e, 0x32,
		0x33, 0xb8, 0x61, 0x6e, 0x63, 0x44, 0x70, 0xf2,
		0x0d, 0xc4, 0x92, 0x8b, 0xcf, 0x36, 0x09, 0xbc
	};
	uint8_t buffer[VB2_PCR_DIGEST_RECOMMENDED_SIZE];

	int algo = CONFIG(TPM1) ? VB2_HASH_SHA1 : VB2_HASH_SHA256;
	int digest_size = CONFIG(TPM1) ? VB2_SHA1_DIGEST_SIZE : VB2_SHA256_DIGEST_SIZE;
	int rv = tpm_setup(is_s3);

	if (rv) {
		printk(BIOS_ERR, "TPM setup failed with 0x%x\n", rv);
		return 0;
	}

	rv = tpm_extend_pcr(CONFIG_PCR_BOOT_MODE, algo, boot_mode_digest, digest_size, "VBOOT: boot mode");
	if (rv) {
		printk(BIOS_ERR, "Boot mode extend failed with 0x%x\n", rv);
		return 0;
	}

	memcpy(buffer, hwid_unknown_digest, sizeof(buffer));

	struct region_device rdev;

	if (fmap_locate_area_as_rdev("GBB", &rdev))
		rdev_readat(&rdev, buffer, 48, 32);

	rv = tpm_extend_pcr(CONFIG_PCR_HWID, algo, buffer, digest_size, "VBOOT: GBB HWID");
	if (rv) {
		printk(BIOS_ERR, "HWID extend failed with 0x%x\n", rv);
		return 0;
	}

	printk(BIOS_INFO, "Successfully locked-out RW secrets\n");

	return 1;
}

/* Verify and select the firmware in the RW image */
int verstage_main(void)
{
	struct vb2_context *ctx;
	vb2_error_t rv;
	bool is_s3 = platform_is_resuming();

	timestamp_add_now(TS_VBOOT_START);

	/* Lockdown SPI flash controller if required */
	if (CONFIG(BOOTMEDIA_LOCK_IN_VERSTAGE))
		boot_device_security_lockdown();

	if (!use_vboot(is_s3)) {
		if (ensure_tpm_rw_is_locked(is_s3))
			return 0;
	}

	/* Set up context and work buffer */
	ctx = vboot_get_context();

	/* Initialize and read nvdata from non-volatile storage. */
	vbnv_init();

	/* Set S3 resume flag if vboot should behave differently when selecting
	 * which slot to boot.  This is only relevant to vboot if the platform
	 * does verification of memory init and thus must ensure it resumes with
	 * the same slot that it booted from. */
	if (CONFIG(RESUME_PATH_SAME_AS_BOOT) &&
		is_s3)
		ctx->flags |= VB2_CONTEXT_S3_RESUME;

	/* Read secdata from TPM. Initialize TPM if secdata not found. We don't
	 * check the return value here because vb2api_fw_phase1 will catch
	 * invalid secdata and tell us what to do (=reboot). */
	timestamp_add_now(TS_TPMINIT_START);
	if (vboot_setup_tpm(ctx) == TPM_SUCCESS) {
		antirollback_read_space_firmware(ctx);
		antirollback_read_space_kernel(ctx);
	}
	timestamp_add_now(TS_TPMINIT_END);

	if (get_recovery_mode_switch()) {
		ctx->flags |= VB2_CONTEXT_FORCE_RECOVERY_MODE;
		if (CONFIG(VBOOT_DISABLE_DEV_ON_RECOVERY))
			ctx->flags |= VB2_CONTEXT_DISABLE_DEVELOPER_MODE;
	}

	if (CONFIG(VBOOT_WIPEOUT_SUPPORTED) &&
		get_wipeout_mode_switch())
		ctx->flags |= VB2_CONTEXT_FORCE_WIPEOUT_MODE;

	if (CONFIG(VBOOT_LID_SWITCH) && !get_lid_switch())
		ctx->flags |= VB2_CONTEXT_NOFAIL_BOOT;

	/* Mainboard/SoC always initializes display. */
	if (!CONFIG(VBOOT_MUST_REQUEST_DISPLAY) || CONFIG(VBOOT_ALWAYS_ENABLE_DISPLAY))
		ctx->flags |= VB2_CONTEXT_DISPLAY_INIT;

	/*
	 * Get boot mode from GSC. This allows us to refuse to boot OS
	 * (with VB2_CONTEXT_NO_BOOT) or to switch to developer mode (with
	 * !VB2_CONTEXT_EC_TRUSTED).
	 *
	 * If there is an communication error, a recovery reason will be set and
	 * vb2api_fw_phase1 will route us to recovery mode.
	 */
	if (CONFIG(TPM_GOOGLE))
		check_boot_mode(ctx);

	if (get_ec_is_trusted())
		ctx->flags |= VB2_CONTEXT_EC_TRUSTED;

	/* Do early init (set up secdata and NVRAM, load GBB) */
	printk(BIOS_INFO, "Phase 1\n");
	rv = vb2api_fw_phase1(ctx);

	if (rv) {
		/*
		 * If vb2api_fw_phase1 fails, check for return value.
		 * If it is set to VB2_ERROR_API_PHASE1_RECOVERY, then continue
		 * into recovery mode.
		 * For any other error code, save context if needed and reboot.
		 */
		if (rv == VB2_ERROR_API_PHASE1_RECOVERY) {
			printk(BIOS_INFO, "Recovery requested (%x)\n", rv);
			vboot_save_data(ctx);
			extend_pcrs(ctx); /* ignore failures */
			goto verstage_main_exit;
		}
		vboot_save_and_reboot(ctx, rv);
	}

	/* Determine which firmware slot to boot (based on NVRAM) */
	printk(BIOS_INFO, "Phase 2\n");
	rv = vb2api_fw_phase2(ctx);
	if (rv)
		vboot_save_and_reboot(ctx, rv);

	/* Try that slot (verify its keyblock and preamble) */
	printk(BIOS_INFO, "Phase 3\n");
	timestamp_add_now(TS_VERIFY_SLOT_START);
	rv = vb2api_fw_phase3(ctx);
	timestamp_add_now(TS_VERIFY_SLOT_END);
	if (rv)
		vboot_save_and_reboot(ctx, rv);

	printk(BIOS_INFO, "Phase 4\n");
	if (CONFIG(VBOOT_CBFS_INTEGRATION)) {
		struct vb2_hash *metadata_hash;
		rv = vb2api_get_metadata_hash(ctx, &metadata_hash);
		if (rv == VB2_SUCCESS)
			rv = handle_digest_result(metadata_hash->raw,
						  vb2_digest_size(metadata_hash->algo));
	} else {
		struct region_device fw_body;
		rv = vboot_locate_firmware(ctx, &fw_body);
		if (rv)
			die_with_post_code(POSTCODE_INVALID_ROM,
					   "Failed to read FMAP to locate firmware");

		rv = hash_body(ctx, &fw_body);
	}

	if (rv)
		vboot_save_and_reboot(ctx, rv);
	vboot_save_data(ctx);

	/* Only extend PCRs once on boot. */
	if (!(ctx->flags & VB2_CONTEXT_S3_RESUME)) {
		timestamp_add_now(TS_TPMPCR_START);
		rv = extend_pcrs(ctx);
		if (rv) {
			printk(BIOS_WARNING, "Failed to extend TPM PCRs (%#x)\n", rv);
			vboot_fail_and_reboot(ctx, VB2_RECOVERY_RO_TPM_U_ERROR, rv);
		}
		timestamp_add_now(TS_TPMPCR_END);
	}

	/* Lock TPM */

	timestamp_add_now(TS_TPMLOCK_START);
	rv = antirollback_lock_space_firmware();
	if (rv) {
		printk(BIOS_INFO, "Failed to lock TPM (%x)\n", rv);
		vboot_fail_and_reboot(ctx, VB2_RECOVERY_RO_TPM_L_ERROR, 0);
	}
	timestamp_add_now(TS_TPMLOCK_END);

	/* Lock rec hash space if available. */
	if (CONFIG(VBOOT_HAS_REC_HASH_SPACE)) {
		rv = antirollback_lock_space_mrc_hash(MRC_REC_HASH_NV_INDEX);
		if (rv) {
			printk(BIOS_INFO, "Failed to lock rec hash space(%x)\n", rv);
			vboot_fail_and_reboot(ctx, VB2_RECOVERY_RO_TPM_REC_HASH_L_ERROR, 0);
		}
	}

	printk(BIOS_INFO, "Slot %c is selected\n",
	       vboot_is_firmware_slot_a(ctx) ? 'A' : 'B');

 verstage_main_exit:
	timestamp_add_now(TS_VBOOT_END);

	return 1;
}
