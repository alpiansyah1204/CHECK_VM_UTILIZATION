#!/usr/bin/env python3
"""
vCenter Disk Usage Scanner
--------------------------
Scans configured vCenter sites for guest filesystems with usage > 80%.
Exports matching results to CSV and Excel, plus a scan-status CSV.

Install:
    python -m pip install pyvmomi requests pandas openpyxl

Notes:
- Guest filesystem usage is collected from VMware Tools.
- vCenter tags are read using the vCenter REST API.
- Configure each site's password in VCENTERS before running. Protect this file.
"""

import getpass
import logging
import ssl
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import pandas as pd
import requests
import urllib3

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim


# ============================================================
# 1. CONFIGURATION: FOUR VCENTER SITES
# ============================================================

VCENTERS = [
    {
        "name": "Site 1",
        "host": "192.168.225.185",
        "username": r"administrator@vsphere.local",
        "password": "REPLACE_WITH_SITE_1_PASSWORD",
    },
    {
        "name": "Site 2",
        "host": "VCENTER_SITE_2",
        "username": r"site2_user@vsphere.local",
        "password": "REPLACE_WITH_SITE_2_PASSWORD",
    },
    {
        "name": "Site 3",
        "host": "VCENTER_SITE_3",
        "username": r"site3_user@vsphere.local",
        "password": "REPLACE_WITH_SITE_3_PASSWORD",
    },
    {
        "name": "Site 4",
        "host": "VCENTER_SITE_4",
        "username": r"site4_user@vsphere.local",
        "password": "REPLACE_WITH_SITE_4_PASSWORD",
    },
]

THRESHOLD_PERCENT = 80.0
OUTPUT_DIR = Path("./vcenter_reports")

# True validates vCenter SSL certificates. If your vCenter uses an
# internal CA, install/trust that CA certificate on this machine.
# Set False only if you knowingly accept the certificate-validation risk.
VERIFY_SSL = True
REQUEST_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

if not VERIFY_SSL:
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )


# ============================================================
# 2. GENERAL HELPERS
# ============================================================

def bytes_to_gb(value):
    if value is None:
        return None
    return round(value / (1024 ** 3), 2)


def connect_vcenter(host, username, password):
    """Connect to vCenter through the vSphere API."""
    context = ssl.create_default_context()

    if not VERIFY_SSL:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return SmartConnect(
        host=host,
        user=username,
        pwd=password,
        port=443,
        sslContext=context,
    )


def get_vm_ips(vm):
    """Get unique IP addresses reported by VMware Tools."""
    guest = getattr(vm, "guest", None)
    if not guest:
        return ""

    addresses = []
    primary_ip = getattr(guest, "ipAddress", None)
    if primary_ip:
        addresses.append(primary_ip)

    for nic in getattr(guest, "net", None) or []:
        ip_config = getattr(nic, "ipConfig", None)
        if not ip_config:
            continue

        for item in getattr(ip_config, "ipAddress", None) or []:
            ip = getattr(item, "ipAddress", None)
            if ip:
                addresses.append(ip)

    result = []
    for ip in addresses:
        if ip.lower().startswith("fe80:"):
            continue
        if ip not in result:
            result.append(ip)

    return ", ".join(result)


# ============================================================
# 3. VCENTER TAG READER
# ============================================================

class VCenterTagReader:
    """Read VM tags using the vCenter REST API."""

    def __init__(self, host, username, password):
        self.base_url = f"https://{host}"
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.session.auth = (username, password)
        self.tag_cache = {}
        self.category_cache = {}

        response = self.session.post(
            f"{self.base_url}/rest/com/vmware/cis/session",
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        session_id = response.json().get("value")
        if not session_id:
            raise RuntimeError(
                "vCenter REST API did not return a session ID"
            )

        self.session.auth = None
        self.session.headers.update({
            "vmware-api-session-id": session_id
        })

    def get_category_name(self, category_id):
        if category_id in self.category_cache:
            return self.category_cache[category_id]

        url = (
            f"{self.base_url}/rest/com/vmware/cis/"
            f"tagging/category/{quote(category_id, safe='')}"
        )
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        category = response.json().get("value", {})
        name = category.get("name", category_id)
        self.category_cache[category_id] = name
        return name

    def get_tag_details(self, tag_id):
        if tag_id in self.tag_cache:
            return self.tag_cache[tag_id]

        url = (
            f"{self.base_url}/rest/com/vmware/cis/"
            f"tagging/tag/{quote(tag_id, safe='')}"
        )
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        tag = response.json().get("value", {})
        tag_name = tag.get("name", tag_id)
        category_id = tag.get("category_id", "")
        category_name = (
            self.get_category_name(category_id)
            if category_id
            else "Uncategorized"
        )

        result = (category_name, tag_name)
        self.tag_cache[tag_id] = result
        return result

    def get_vm_tags(self, vm_moid):
        """List tags attached to a VM managed object (e.g. vm-123)."""
        url = (
            f"{self.base_url}/rest/com/vmware/cis/"
            "tagging/tag-association"
            "?~action=list-attached-tags"
        )

        response = self.session.post(
            url,
            json={
                "object_id": {
                    "id": vm_moid,
                    "type": "VirtualMachine",
                }
            },
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        tag_ids = response.json().get("value", [])
        tag_names = []

        for tag_id in tag_ids:
            try:
                category, name = self.get_tag_details(tag_id)
                tag_names.append(f"{category}: {name}")
            except Exception as exc:
                logging.warning(
                    "Cannot resolve tag %s: %s", tag_id, exc
                )
                tag_names.append(tag_id)

        return "; ".join(tag_names) if tag_names else "No tags"

    def close(self):
        self.session.close()


# ============================================================
# 4. RECORD SCAN STATUS
# ============================================================

def add_status(
    statuses,
    site,
    endpoint,
    vm_name="",
    hostname="",
    ip_address="",
    power_state="",
    scan_status="",
):
    statuses.append({
        "Site": site,
        "vCenter Endpoint": endpoint,
        "VM Name": vm_name,
        "Hostname": hostname,
        "IP Address": ip_address,
        "Power State": power_state,
        "Scan Status": scan_status,
    })


# ============================================================
# 5. SCAN ONE VCENTER
# ============================================================

def scan_vcenter(site, endpoint, username, password):
    matches = []
    statuses = []
    service_instance = None
    tag_reader = None
    container = None

    try:
        logging.info("[%s] Connecting to %s", site, endpoint)
        service_instance = connect_vcenter(
            endpoint, username, password
        )
        content = service_instance.RetrieveContent()

        container = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.VirtualMachine],
            True,
        )

        # A tag API problem should not prevent disk scanning.
        try:
            tag_reader = VCenterTagReader(
                endpoint, username, password
            )
            logging.info("[%s] Tag API connected", site)
        except Exception as exc:
            logging.warning(
                "[%s] Tag API unavailable: %s", site, exc
            )

        logging.info(
            "[%s] Found %d VM(s)", site, len(container.view)
        )

        for vm in container.view:
            try:
                vm_name = vm.name
                guest = getattr(vm, "guest", None)
                hostname = (
                    getattr(guest, "hostName", None) or ""
                    if guest else ""
                )
                ip_address = get_vm_ips(vm)
                power_state = str(vm.runtime.powerState)

                if tag_reader:
                    try:
                        tags = tag_reader.get_vm_tags(vm._moId)
                    except Exception as exc:
                        logging.warning(
                            "[%s] Tag lookup failed for %s: %s",
                            site, vm_name, exc
                        )
                        tags = "Tag lookup failed"
                else:
                    tags = "Tag lookup unavailable"

                if power_state != "poweredOn":
                    add_status(
                        statuses, site, endpoint, vm_name,
                        hostname, ip_address, power_state,
                        "Skipped: VM is powered off",
                    )
                    continue

                if not guest:
                    add_status(
                        statuses, site, endpoint, vm_name,
                        hostname, ip_address, power_state,
                        "Guest information unavailable",
                    )
                    continue

                tools_status = str(
                    getattr(guest, "toolsRunningStatus", "")
                )
                disks = getattr(guest, "disk", None) or []

                if not disks:
                    status = (
                        "No guest disk data; check VMware Tools"
                    )
                    if tools_status != "guestToolsRunning":
                        status += (
                            f" (Tools status: "
                            f"{tools_status or 'unknown'})"
                        )
                    add_status(
                        statuses, site, endpoint, vm_name,
                        hostname, ip_address, power_state, status,
                    )
                    continue

                high_usage_found = False
                usable_disk_found = False

                for disk in disks:
                    capacity = getattr(disk, "capacity", None)
                    free_space = getattr(disk, "freeSpace", None)
                    disk_path = (
                        getattr(disk, "diskPath", None) or ""
                    )

                    if (
                        capacity is None
                        or free_space is None
                        or capacity <= 0
                        or free_space < 0
                        or free_space > capacity
                    ):
                        continue

                    usable_disk_found = True
                    used_space = capacity - free_space
                    usage_percent = used_space / capacity * 100

                    if usage_percent > THRESHOLD_PERCENT:
                        high_usage_found = True
                        matches.append({
                            "Site": site,
                            "vCenter Endpoint": endpoint,
                            "VM Name": vm_name,
                            "Hostname": hostname,
                            "IP Address": ip_address,
                            "VM Tags": tags,
                            "Filesystem / Disk": disk_path,
                            "Capacity (GB)": bytes_to_gb(capacity),
                            "Used (GB)": bytes_to_gb(used_space),
                            "Free (GB)": bytes_to_gb(free_space),
                            "Usage (%)": round(usage_percent, 2),
                            "Power State": power_state,
                        })

                        logging.warning(
                            "[%s] %s | %s | %.2f%%",
                            site, vm_name,
                            disk_path or "Unknown filesystem",
                            usage_percent,
                        )

                if not usable_disk_found:
                    status = (
                        "Guest disk entries exist but no valid "
                        "capacity/free-space values were available"
                    )
                elif high_usage_found:
                    status = (
                        f"Found filesystem usage > "
                        f"{THRESHOLD_PERCENT}%"
                    )
                else:
                    status = (
                        f"Scanned; no filesystem exceeded "
                        f"{THRESHOLD_PERCENT}%"
                    )

                add_status(
                    statuses, site, endpoint, vm_name,
                    hostname, ip_address, power_state, status,
                )

            except Exception as exc:
                logging.exception(
                    "[%s] Failed to scan VM %s",
                    site, getattr(vm, "name", "Unknown"),
                )
                add_status(
                    statuses, site, endpoint,
                    vm_name=getattr(vm, "name", ""),
                    scan_status=f"VM scan failed: {exc}",
                )

    except Exception as exc:
        logging.exception("[%s] vCenter scan failed", site)
        add_status(
            statuses, site, endpoint,
            scan_status=f"vCenter connection/scan failed: {exc}",
        )

    finally:
        if container:
            container.Destroy()
        if tag_reader:
            tag_reader.close()
        if service_instance:
            Disconnect(service_instance)

    return matches, statuses


# ============================================================
# 6. EXPORT CSV AND EXCEL
# ============================================================

def export_reports(matches, statuses):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    csv_path = OUTPUT_DIR / f"vm_disk_over_80_{timestamp}.csv"
    excel_path = OUTPUT_DIR / f"vm_disk_over_80_{timestamp}.xlsx"
    status_path = OUTPUT_DIR / f"vm_scan_status_{timestamp}.csv"

    columns = [
        "Site",
        "vCenter Endpoint",
        "VM Name",
        "Hostname",
        "IP Address",
        "VM Tags",
        "Filesystem / Disk",
        "Capacity (GB)",
        "Used (GB)",
        "Free (GB)",
        "Usage (%)",
        "Power State",
    ]

    df = pd.DataFrame(matches, columns=columns)
    status_df = pd.DataFrame(
        statuses,
        columns=[
            "Site", "vCenter Endpoint", "VM Name", "Hostname",
            "IP Address", "Power State", "Scan Status",
        ],
    )

    df.to_csv(csv_path, index=False, encoding="utf-8-sig")
    status_df.to_csv(
        status_path, index=False, encoding="utf-8-sig"
    )

    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        df.to_excel(
            writer, sheet_name="Disk Usage Over 80%", index=False
        )
        status_df.to_excel(
            writer, sheet_name="Scan Status", index=False
        )

        for sheet in writer.sheets.values():
            sheet.freeze_panes = "A2"
            if sheet.max_row >= 1 and sheet.max_column >= 1:
                sheet.auto_filter.ref = sheet.dimensions

            for column_cells in sheet.columns:
                max_length = max(
                    len(str(cell.value or ""))
                    for cell in column_cells
                )
                sheet.column_dimensions[
                    column_cells[0].column_letter
                ].width = min(max_length + 2, 55)

    logging.info("CSV report: %s", csv_path.resolve())
    logging.info("Excel report: %s", excel_path.resolve())
    logging.info("Status report: %s", status_path.resolve())
    logging.info("Filesystem entries above threshold: %d", len(df))


# ============================================================
# 7. MAIN
# ============================================================

def main():
    print("=" * 65)
    print("vCenter Guest Disk Usage Scanner")
    print(f"Threshold: usage > {THRESHOLD_PERCENT}%")
    print(f"Configured vCenters: {len(VCENTERS)}")
    print("=" * 65)

    all_matches = []
    all_statuses = []

    for vc in VCENTERS:
        site = vc["name"]
        endpoint = vc["host"]
        username = vc["username"]
        password = vc["password"]

        if endpoint.startswith("VCENTER_SITE_"):
            logging.warning(
                "[%s] Skipping placeholder endpoint: %s",
                site, endpoint,
            )
            add_status(
                all_statuses, site, endpoint,
                scan_status="Skipped: configure actual endpoint",
            )
            continue

        if not password or password.startswith("REPLACE_WITH_"):
            logging.error(
                "[%s] Password placeholder has not been replaced; skipping site",
                site,
            )
            add_status(
                all_statuses, site, endpoint,
                scan_status="Skipped: configure password in VCENTERS",
            )
            continue

        print(f"\n{'-' * 50}")
        print(f"Site     : {site}")
        print(f"Endpoint : {endpoint}")
        print(f"Username : {username}")
        print("Password : configured in script")

        matches, statuses = scan_vcenter(
            site, endpoint, username, password
        )
        all_matches.extend(matches)
        all_statuses.extend(statuses)

    export_reports(all_matches, all_statuses)

    print("\n" + "=" * 65)
    print("SCAN COMPLETED")
    print(
        f"Filesystem entries > {THRESHOLD_PERCENT}%: "
        f"{len(all_matches)}"
    )
    print(f"Output directory: {OUTPUT_DIR.resolve()}")
    print("=" * 65)

if __name__ == "__main__":
    main()
