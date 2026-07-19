rule UPX_Packed
{
    meta:
        description = "Detects UPX-packed PE files by section names and signature strings"
        author = "CaseIntel"
    tags = "packer"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "UPX!" ascii
    condition:
        any of them
}

rule Generic_Anti_Debug
{
    meta:
        description = "Common anti-debugging API references"
        author = "CaseIntel"
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
        $c = "NtQueryInformationProcess" ascii
    condition:
        any of them
}
