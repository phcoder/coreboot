/* SPDX-License-Identifier: GPL-2.0-only */

#include <acpi/acpigen_pci.h>
#include <amdblocks/ioapic.h>
#include <amdblocks/data_fabric.h>
#include <amdblocks/memmap.h>
#include <amdblocks/root_complex.h>
#include <amdblocks/smn.h>
#include <arch/ioapic.h>
#include <cbmem.h>
#include <console/console.h>
#include <device/device.h>
#include <types.h>

#include <vendorcode/amd/opensil/genoa_poc/opensil.h>

#define IOHC_IOAPIC_BASE_ADDR_LO 0x2f0

void read_soc_memmap_resources(struct device *domain, unsigned long *idx)
{
	ram_from_to(domain, (*idx)++, 0, 0xa0000);
	mmio_from_to(domain, (*idx)++, 0xa0000, 0xc0000); // legacy VGA
	reserved_ram_from_to(domain, (*idx)++, 0xc0000, 1 * MiB); // Option ROM

	uint32_t mem_usable = (uintptr_t)cbmem_top();
	uintptr_t early_reserved_dram_start, early_reserved_dram_end;
	const struct memmap_early_dram *e = memmap_get_early_dram_usage();

	early_reserved_dram_start = e->base;
	early_reserved_dram_end = e->base + e->size;

	// 1MB - bottom of DRAM reserved for early coreboot usage
	ram_from_to(domain, (*idx)++, 1 * MiB, early_reserved_dram_start);

	// DRAM reserved for early coreboot usage
	reserved_ram_from_to(domain, (*idx)++, early_reserved_dram_start,
			     early_reserved_dram_end);

	// top of DRAM consumed early - low top usable RAM
	// cbmem_top() accounts for low UMA and TSEG if they are used.
	ram_from_to(domain, (*idx)++, early_reserved_dram_end,
		    mem_usable);

	add_opensil_memmap(domain, idx);
}

static void genoa_domain_set_resources(struct device *domain)
{
	if (domain->downstream->bridge_ctrl & PCI_BRIDGE_CTL_VGA) {
		printk(BIOS_DEBUG, "Setting VGA decoding for domain 0x%x\n",
		       domain->path.domain.domain);
		const union df_vga_en vga_en = {
			.ve = 1,
			.dst_fabric_id = get_iohc_fabric_id(domain),
		};
		data_fabric_broadcast_write32(DF_VGA_EN, vga_en.raw);
	}

	pci_domain_set_resources(domain);

	/* Enable IOAPIC memory decoding */
	struct resource *res = probe_resource(domain, IOMMU_IOAPIC_IDX);
	if (res) {
		const uint32_t iohc_misc_base = get_iohc_misc_smn_base(domain);
		uint32_t ioapic_base = smn_read32(iohc_misc_base | IOHC_IOAPIC_BASE_ADDR_LO);
		ioapic_base |= (1 << 0);
		smn_write32(iohc_misc_base | IOHC_IOAPIC_BASE_ADDR_LO, ioapic_base);
	}
}

static const char *genoa_domain_acpi_name(const struct device *domain)
{
	const char *domain_acpi_names[4] = {
		"S0B0",
		"S0B1",
		"S0B2",
		"S0B3",
	};

	if (domain->path.domain.domain < ARRAY_SIZE(domain_acpi_names))
		return domain_acpi_names[domain->path.domain.domain];

	return NULL;
}

struct device_operations genoa_pci_domain_ops = {
	.read_resources	= amd_pci_domain_read_resources,
	.set_resources	= genoa_domain_set_resources,
	.scan_bus	= amd_pci_domain_scan_bus,
	.init		= amd_pci_domain_init,
	.acpi_name	= genoa_domain_acpi_name,
	.acpi_fill_ssdt	= pci_domain_fill_ssdt,
};
