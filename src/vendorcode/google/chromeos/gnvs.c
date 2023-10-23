/* SPDX-License-Identifier: GPL-2.0-only */

#include <acpi/acpi.h>
#include <acpi/acpigen.h>
#include <bootstate.h>
#include <types.h>
#include <string.h>
#include <stdlib.h>
#include <cbfs.h>
#include <cbmem.h>
#include <console/console.h>
#include <ec/google/chromeec/ec.h>
#include <fmap.h>
#include <security/vboot/vbnv.h>
#include <security/vboot/vboot_common.h>
#include <smbios.h>

#include "chromeos.h"
#include "gnvs.h"

static struct chromeos_acpi *chromeos_acpi;

static size_t chromeos_vpd_region(const char *region, uintptr_t *base)
{
	struct region_device vpd;

	if (fmap_locate_area_as_rdev(region, &vpd))
		return 0;

	*base = (uintptr_t)rdev_mmap_full(&vpd);

	return region_device_sz(&vpd);
}

static void chromeos_init_chromeos_acpi(void *unused)
{
	size_t vpd_size;
	uintptr_t vpd_base = 0;

	chromeos_acpi = cbmem_add(CBMEM_ID_ACPI_CNVS, sizeof(struct chromeos_acpi));
	if (!chromeos_acpi)
		return;

	/* Retain CNVS contents on S3 resume path. */
	if (acpi_is_wakeup_s3())
		return;

#if CONFIG(VBOOT_HYBRID)
	memset(chromeos_acpi, 0, sizeof(*chromeos_acpi));
#endif

	vpd_size = chromeos_vpd_region("RO_VPD", &vpd_base);
	if (vpd_size && vpd_base) {
		chromeos_acpi->vpd_ro_base = vpd_base;
		chromeos_acpi->vpd_ro_size = vpd_size;
	}

	vpd_size = chromeos_vpd_region("RW_VPD", &vpd_base);
	if (vpd_size && vpd_base) {
		chromeos_acpi->vpd_rw_base = vpd_base;
		chromeos_acpi->vpd_rw_size = vpd_size;
	}

	/* In case of hybrid we may not have depthcharge,
	   so fill CBNV ourselves, so that crossystem works properly.  */
#if CONFIG(VBOOT_HYBRID)
	chromeos_acpi->vbt0 = 0; /* Boot reason other */
	chromeos_acpi->vbt1 = 0; /* Main fw recovery */
#if CONFIG(EC_GOOGLE_CHROMEEC)
	chromeos_acpi->vbt2 = !google_ec_running_ro();
#else
	chromeos_acpi->vbt2 = 1; /* Assume RW */
#endif
	chromeos_acpi->vbt3 = 0; /* No switches */

	struct region_device rdev;
	if (fmap_locate_area_as_rdev("GBB", &rdev)) {
		struct {
			uint32_t hwid_offset;
			uint32_t hwid_size;
		} hwid_pointer = {0, 0};
		rdev_readat(&rdev, &hwid_pointer, 16, 8);
		if (hwid_pointer.hwid_size > sizeof(chromeos_acpi->vbt4))
			hwid_pointer.hwid_size = sizeof(chromeos_acpi->vbt4);
		rdev_readat(&rdev, chromeos_acpi->vbt4,
			    hwid_pointer.hwid_offset, hwid_pointer.hwid_size);
	}
	const char fwid[] = CONFIG_VBOOT_FWID_MODEL CONFIG_VBOOT_FWID_VERSION;
	const uint32_t fwid_size = sizeof(fwid) < sizeof(chromeos_acpi->vbt5) ? sizeof(fwid) : sizeof(chromeos_acpi->vbt5);
	memcpy(chromeos_acpi->vbt5, fwid, fwid_size);
	memcpy(chromeos_acpi->vbt6, fwid, fwid_size);
	chromeos_acpi->vbt7 = 1; /* Firmware type: normal */
	chromeos_acpi->vbt8 = 0; /* Recovery reason: none */
	chromeos_acpi->vbt9 = (u32) cbmem_entry_find(CBMEM_ID_FMAP);
	/* Missing: VDAT. */
#endif
}

BOOT_STATE_INIT_ENTRY(BS_PRE_DEVICE, BS_ON_EXIT, chromeos_init_chromeos_acpi, NULL);

void chromeos_set_me_hash(u32 *hash, int len)
{
	if ((len*sizeof(u32)) > sizeof(chromeos_acpi->mehh))
		return;

	/* Copy to NVS. */
	if (chromeos_acpi)
		memcpy(chromeos_acpi->mehh, hash, len*sizeof(u32));
}

void chromeos_set_ramoops(void *ram_oops, size_t size)
{
	if (!chromeos_acpi)
		return;

	printk(BIOS_DEBUG, "Ramoops buffer: 0x%zx@%p.\n", size, ram_oops);
	chromeos_acpi->ramoops_base = (uintptr_t)ram_oops;
	chromeos_acpi->ramoops_len = size;
}

void smbios_type0_bios_version(uintptr_t address)
{
	if (!chromeos_acpi)
		return;
	/* Location of smbios_type0.bios_version() string filled with spaces. */
	chromeos_acpi->vbt10 = address;
}

void acpi_fill_cnvs(void)
{
	const struct opregion cnvs_op = OPREGION("CNVS", SYSTEMMEMORY, (uintptr_t)chromeos_acpi,
						 sizeof(*chromeos_acpi));

	if (!chromeos_acpi)
		return;

	acpigen_write_scope("\\");
	acpigen_write_opregion(&cnvs_op);
	acpigen_pop_len();

	chromeos_acpi_gpio_generate();
}
