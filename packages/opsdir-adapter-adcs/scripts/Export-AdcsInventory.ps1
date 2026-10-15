<#
.SYNOPSIS
    Export one AD CS certification authority's issued-certificate inventory, publication URLs and templates as the
    JSON opsdir's adcs/inventory importer reads (format opsdir-adcs-inventory, version 1). Metadata only.

.DESCRIPTION
    Runs on a Windows host that reaches the CA (its own host, or one with the CA's RPC/DCOM open to it), as an account
    holding the CA's Read permission (MS-CSRA: Read is enough to open the database view; Issue and Manage
    Certificates isn't needed). It uses only Microsoft's documented COM interfaces:

      ICertView (CertificateAuthority.View)    OpenConnection("COMPUTERNAME\CANAME"), SetResultColumnCount,
                                               SetResultColumn / GetColumnIndex by schema name, SetRestriction on
                                               Request.Disposition (20 issued, 21 revoked), OpenView, and each row's
                                               IEnumCERTVIEWCOLUMN GetName / GetValue (typed VARIANTs)
      ICertAdmin2 (CertificateAuthority.Admin) GetConfigEntry: CRLPublicationURLs, CACertPublicationURLs;
                                               GetCAProperty: CR_PROP_TEMPLATES

    It never selects an archived-key column (RawArchivedKey, KeyRecoveryHashes) or the request's own binary: only
    the columns below, and RawCertificate (public) to compute the certificate's SHA-256 and subject, which are written
    instead of it. Check a column's availability with `certutil -config "HOST\CA" -schema`.

    NOT YET RUN against a CA (opsdir is developed without Windows): the CA team reviews and runs it once and compares
    a few rows with `certutil -gmt -view` (README, Known limits) before its output is relied on.

.PARAMETER Config
    The CA's configuration string, COMPUTERNAME\CANAME (ICertView::OpenConnection).

.PARAMETER OutFile
    Where to write the JSON (one file per CA: put it in the export's ca/ folder as <CA name>.json).

.PARAMETER DnsName
    The CA host's DNS name, filled into %1 of its publication URLs. Default: this host's FQDN.

.PARAMETER NetbiosName
    The CA host's NetBIOS name, filled into %2. Default: the COMPUTERNAME part of -Config.

.EXAMPLE
    .\Export-AdcsInventory.ps1 -Config "PKI-ISS-02\Example Aero Issuing CA 2" -OutFile ".\ca\Example Aero Issuing CA 2.json"
#>
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string]$DnsName = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName,
    [string]$NetbiosName = ($Config -split '\\', 2)[0]
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Version = '1.0'
$Columns = @('RequestID', 'SerialNumber', 'NotBefore', 'NotAfter', 'CertificateTemplate', 'Request.RequesterName',
             'Request.Disposition', 'Request.RevokedWhen', 'Request.RevokedEffectiveWhen', 'Request.RevokedReason',
             'RawCertificate')
$CVRC_COLUMN_SCHEMA = 0          # GetColumnIndex: the column by its schema name
$CVR_SEEK_GE = 0x8; $CVR_SEEK_LE = 0x4; $CVR_SORT_NONE = 0
$CV_OUT_BASE64 = 0x1             # GetValue: binary columns as base64 text
$CR_PROP_TEMPLATES = 0x1d; $PROPTYPE_STRING = 4

function ConvertTo-Utc($Value) {
    # VARIANT DATE values from ICertView, taken as UTC (CERTTIME is UTC; see README, Known limits)
    if ($null -eq $Value) { return $null }
    return ([datetime]::SpecifyKind([datetime]$Value, [System.DateTimeKind]::Utc)).ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Read-Rows($View) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $rows = New-Object System.Collections.ArrayList
    $enumRows = $View.OpenView()
    while ($enumRows.Next() -ne -1) {
        $row = [ordered]@{}
        $enumCols = $enumRows.EnumCertViewColumn()
        while ($enumCols.Next() -ne -1) {
            $name = $enumCols.GetName()
            $value = $enumCols.GetValue($CV_OUT_BASE64)
            if ($name -eq 'RawCertificate') {
                if ($value) {
                    $bytes = [Convert]::FromBase64String(($value -replace '\s', ''))
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $bytes)
                    $row['SHA256'] = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '')
                    $row['Subject'] = $cert.Subject
                } else { $row['SHA256'] = $null; $row['Subject'] = $null }
            } elseif ($value -is [datetime]) { $row[$name] = ConvertTo-Utc $value }
            else { $row[$name] = $value }
        }
        [void]$rows.Add($row)
    }
    return , $rows
}

$doc = [ordered]@{
    format = 'opsdir-adcs-inventory'; version = 1; exporter = "Export-AdcsInventory $Version"
    exportedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    config = $Config; caName = ($Config -split '\\', 2)[1]; dnsName = $DnsName; netbiosName = $NetbiosName
    complete = $false; error = $null; templates = @(); crlPublicationUrls = @(); caCertPublicationUrls = @(); rows = @()
}
try {
    $admin = New-Object -ComObject CertificateAuthority.Admin
    $doc.crlPublicationUrls = @($admin.GetConfigEntry($Config, '', 'CRLPublicationURLs'))
    $doc.caCertPublicationUrls = @($admin.GetConfigEntry($Config, '', 'CACertPublicationURLs'))
    $templates = $admin.GetCAProperty($Config, $CR_PROP_TEMPLATES, 0, $PROPTYPE_STRING, 0)
    $doc.templates = @(($templates -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $view = New-Object -ComObject CertificateAuthority.View
    $view.OpenConnection($Config)
    $disposition = $view.GetColumnIndex($CVRC_COLUMN_SCHEMA, 'Request.Disposition')
    $view.SetRestriction($disposition, $CVR_SEEK_GE, $CVR_SORT_NONE, 20)
    $view.SetRestriction($disposition, $CVR_SEEK_LE, $CVR_SORT_NONE, 21)
    $view.SetResultColumnCount($Columns.Count)
    foreach ($c in $Columns) { $view.SetResultColumn($view.GetColumnIndex($CVRC_COLUMN_SCHEMA, $c)) }
    $doc.rows = Read-Rows $view
    $doc.complete = $true
} catch {
    $doc.error = $_.Exception.Message
}
$doc | ConvertTo-Json -Depth 4 | Set-Content -Path $OutFile -Encoding UTF8
