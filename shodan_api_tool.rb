#!/usr/bin/env ruby
#
# Shodan API Search Assistant
# By: Hood3dRob1n
#

########### ENTER API KEY HERE  ###########
APIKEY='YOURSHODANAPIKEYGOESRIGHTINHEREYO'#
###########################################

##### STD GEMS #######
require 'fileutils'  #
require 'optparse'   #
require 'resolv'     #
#### NON-STD GEMS ####
require 'rubygems'   #
require 'colorize'   #
require 'curb'       #
require 'json'       #
require 'nokogiri'   #
######################

HOME=File.expand_path(File.dirname(__FILE__))
RESULTS = HOME + '/results/'

# Banner
def banner
  puts
  puts "Shodan API Search Assistant".light_green
  puts "By".light_green + ": Hood3dRob1n".white
end

# Clear Terminal
def cls
  if RUBY_PLATFORM =~ /win32|win64|\.NET|windows|cygwin|mingw32/i
    system('cls')
  else
    system('clear')
  end
end

# Custom ShodanAPI Class :)
# The pre-built option is broken and doesn't work in several places....
# So we re-wrote it!
class ShodanAPI
  # Initialize ShodanAPI via passed API Key
  def initialize(apikey)
    @url="http://www.shodanhq.com/api/"
    if shodan_connect(apikey)
        @key=apikey
    end
  end

  # Check API Key against API Info Query
  # Return True on success, False on Error or Failure
  def shodan_connect(apikey)
    url = @url + "info?key=#{apikey}"
    begin
      c = Curl::Easy.perform(url)
      if c.body_str =~ /"unlocked_left": \d+, "telnet": .+, "plan": ".+", "https": .+, "unlocked": .+/i
        results = JSON.parse(c.body_str)
        @plan = results['plan']
        @unlocked = results['unlocked']
        @unlocks = results['unlocked_left']
        @https = results['https']
        @telnet = results['telnet']
        return true
      elsif c.body_str =~ /"error": "API access denied"/i
        puts "Access Denied using API Key '#{apikey}'".light_red + "!".white
        puts "Check Key & Try Again".light_red + "....".white
        return false
      else
        puts "Unknown Problem with Connection to Shodan API".light_green + "!".white
        return false
      end
    rescue => e
      puts "Problem with Connection to Shodan API".light_red + "!".white
      puts "\t=> #{e}"
      return false
    end
  end

  # Just checks our key is working (re-using shodan_connect so updates @unlocks)
  # Returns True or False
  def connected?
    if shodan_connect(@key)
      return true
    else
      return  false
    end
  end

  # Return the number of unlocks remaining
  def unlocks
    if shodan_connect(@key)
      return @unlocks.to_i
    else
      return nil
    end
  end

  # Check if HTTPS is Enabled
  def https?
    if shodan_connect(@key)
      if @https
        return true
      else
        return false
      end
    else
      return false
    end
  end

  # Check if Telnet is Enabled
  def telnet?
    if shodan_connect(@key)
      if @telnet
        return true
      else
        return false
      end
    else
      return false
    end
  end

  # Actually display Basic Info for current API Key
  def info
    url = @url + 'info?key=' + @key
    begin
      c = Curl::Easy.perform(url)
      results = JSON.parse(c.body_str)
      puts
      puts "Shodan API Key Confirmed".light_green + "!".white
      puts "API Key".light_green + ": #{@key}".white
      puts "Plan Type".light_green + ": #{results['plan']}".white
      puts "Unlocked".light_green + ": #{results['unlocked']}".white
      puts "Unlocks Remaining".light_green + ": #{results['unlocked_left']}".white
      puts "HTTPS Enabled".light_green + ": #{results['https']}".white
      puts "Telnet Enabled".light_green + ": #{results['telnet']}".white
      return true
    rescue => e
      puts "Problem with Connection to Shodan API".light_red + "!".white
      puts "\t=> #{e}".white
      return false
    end
  end

  # Lookup all available information for a specific IP address
  # Returns results hash or nil
  def host(ip)
    url = @url + 'host?ip=' + ip + '&key=' + @key
    begin
      c = Curl::Easy.perform(url)
      results = JSON.parse(c.body_str)
      return results
    rescue => e
      puts "Problem running Host Search".light_red + "!".white
      puts "\t=> #{e}".white
      return nil
    end
  end

  # Returns the number of devices that a search query found
  # Unrestricted usage of all advanced filters
  # Return results count or nil on failure
  def count(string)
    url = @url + 'count?q=' + string + '&key=' + @key
    begin
      c = Curl::Easy.perform(url)
      results = JSON.parse(c.body_str)
      return results['total']
    rescue => e
      puts "Problem grabbing results count".light_red + "!".white
      puts "\t=> #{e}".white
      return nil
    end
  end

  # Search Shodan for devices using a search query
  # Returns results hash or nil
  def search(string, filters={})
    prem_filters =  [ 'city', 'country', 'geo', 'net', 'before', 'after', 'org', 'isp', 'title', 'html' ]
    cheap_filters = [ 'hostname', 'os', 'port' ]
    url = @url + 'search?q=' + string
    if not filters.empty?
      filters.each do |k, v|
        if cheap_filters.include?(k)
          url += ' ' + k + ":\"#{v}\""
        end
        if prem_filters.include?(k)
          if @unlocks.to_i > 1
            url += ' ' + k + ":\"#{v}\""
            @unlocks = @unlocks.to_i - 1 # Remove an unlock for use of filter
          else
            puts "Not Enough Unlocks Left to run Premium Filter Search".light_red + "!".white
            puts "Try removing '#{k}' filter and trying again".light_red + "....".white
            return nil
          end
        end
      end
    end
    url += '&key=' + @key
    begin
      c = Curl::Easy.perform(url)
      results = JSON.parse(c.body_str)
      return results
    rescue => e
      puts "Problem running Shodan Search".light_red + "!".white
      puts "\t=> #{e}".white
      return nil
    end
  end

  # Quick Search Shodan for devices using a search query
  # Results are limited to only the IP addresses
  # Returns results array or nil
  def quick_search(string, filters={})
    prem_filters =  [ 'city', 'country', 'geo', 'net', 'before', 'after', 'org', 'isp', 'title', 'html' ]
    cheap_filters = [ 'hostname', 'os', 'port' ]
    url = @url + 'search?q=' + string
    if not filters.empty?
      filters.each do |k, v|
        if cheap_filters.include?(k)
          url += ' ' + k + ":\"#{v}\""
        end
        if prem_filters.include?(k)
          if @unlocks.to_i > 1
            url += ' ' + k + ":\"#{v}\""
            @unlocks = @unlocks.to_i - 1
          else
            puts "Not Enough Unlocks Left to run Premium Filter Search".light_red + "!".white
            puts "Try removing '#{k}' filter and trying again".light_red + "....".white
            return nil
          end
        end
      end
    end
    url += '&key=' + @key
    begin
      ips=[]
      c = Curl::Easy.perform(url)
      results = JSON.parse(c.body_str)
      results['matches'].each do |host|
       ips << host['ip']
      end
      return ips
    rescue => e
      puts "Problem running Shodan Quick Search".light_red + "!".white
      puts "\t=> #{e}".white
      return nil
    end
  end

  # Perform Shodan Exploit Search as done on Web
  # Provide Search String and source
  # Source can be: metasploit, exploitdb, or cve
  # Returns results hash array on success: { downloadID => { link => description } }
  # Returns nil on failure
  def sploit_search(string, source)
    sources = [ "metasploit", "exploitdb", "cve" ]
    if sources.include?(source.downcase)
      sploits = 'https://exploits.shodan.io/?q=' + string + ' source:"' + source.downcase + '"'
      begin
        results={}
        c = Curl::Easy.perform(sploits)
        page = Nokogiri::HTML(c.body_str) # Parsable doc object now
        # Enumerate target section, parse out link & description
        page.css('div[class="search-result well"]').each do |linematch|
          if linematch.to_s =~ /<div class="search-result well">\s+<a href="(.+)"\s/
            link=$1
          end
          if linematch.to_s =~ /class="title">(.+)\s+<\/a>/
            desc=$1.gsub('<em>', '').gsub('</em>', '')
          end
          case source.downcase
          when 'cve'
            dl_id = 'N/A for CVE Search'
          when 'exploitdb'
            dl_id = link.split('/')[-1] unless link.nil?
          when 'metasploit'
            dl_id = link.sub('http://www.metasploit.com/', '').sub(/\/$/, '') unless link.nil?
          end
          results.store(dl_id, { link => desc}) unless (link.nil? or link == '') or (desc.nil? or desc == '') or (dl_id.nil? or dl_id == 'N/A for CVE Search')
        end
        return results
      rescue Curl::Err::ConnectionFailedError => e
        puts "Shitty connection yo".light_red + ".....".white
        return nil
      rescue => e
        puts "Unknown connection problem".light_red + ".....".white
        puts "\t=> #{e}".white
        return nil
      end
    else
      puts "Invalid Search Source Requested".light_red + "!".white
      return nil
    end
  end

  # Download Exploit Code from Exploit-DB or MSF Github Page
  # By passing in the Download ID (which can be seen in sploit_search() results)
  # Return { 'Download' => dl_link, 'Viewing' => v_link, 'Exploit' => c.body_str }
  # or nil on failure
  def sploit_download(id, source)
    sources = [ "metasploit", "exploitdb" ]
    if sources.include?(source.downcase)
      case source.downcase
      when 'exploitdb'
        dl_link = "http://www.exploit-db.com/download/#{id}/"
        v_link = "http://www.exploit-db.com/exploits/#{id}/"
      when 'metasploit'
        dl_link = "https://raw.github.com/rapid7/metasploit-framework/master/#{id.sub('/exploit/', '/exploits/')}.rb"
        v_link = "http://www.rapid7.com/db/#{id}/"
      end
      begin
        c = Curl::Easy.perform(dl_link)
        page = Nokogiri::HTML(c.body_str) # Parsable doc object now
        results = { 'Download' => dl_link, 'Viewing' => v_link, 'Exploit' => c.body_str }
        return results
      rescue Curl::Err::ConnectionFailedError => e
        puts "Shitty connection yo".light_red + ".....".white
        return false
      rescue => e
        puts "Unknown connection problem".light_red + ".....".white
        puts "#{e}".light_red
        return false
      end
    else
      puts "Invalid Download Source Requested".light_red + "!".white
      return false
    end
  end
end

### MAIN ###
options = {}
optparse = OptionParser.new do |opts| 
  opts.banner = "Usage:".light_green + "#{$0} ".white + "[".light_green + "OPTIONS".white + "]".light_green
  opts.separator ""
  opts.separator "EX:".light_green + " #{$0} -s cisco-ios".white
  opts.separator "EX:".light_green + " #{$0} -h 217.140.75.46".white
  opts.separator "EX:".light_green + " #{$0} --quick-search IIS/5.1".white
  opts.separator "EX:".light_green + " #{$0} -S exploitdb -x udev".white
  opts.separator "EX:".light_green + " #{$0} -d 8678 -S exploitdb".white
  opts.separator "EX:".light_green + " #{$0} --source metasploit --exploit-search udev".white
  opts.separator "EX:".light_green + " #{$0} -S metasploit -d modules/exploit/linux/local/udev_netlink".white
  opts.separator ""
  opts.separator "Options: ".light_green
  opts.on('-q', '--quick-search STRING', "\n\tShodan Quick Search".white) do |search_str|
    options[:method] = 3 # 1=> Normal, 2=> IP, 3=> Quick, 4=>Exploit Search, 5=>Exploit Download
    options[:search] = search_str.chomp
  end
  opts.on('-s', '--shodan-search STRING', "\n\tShodan Search".white) do |search_str|
    options[:method] = 1 # 1=> Normal, 2=> IP, 3=> Quick, 4=>Exploit Search, 5=>Exploit Download
    options[:search] = search_str.chomp
  end
  opts.on('-h', '--host-search HOST', "\n\tShodan Host Search against IP".white) do |search_str|
    options[:method] = 2 # 1=> Normal, 2=> IP, 3=> Quick, 4=>Exploit Search, 5=>Exploit Download
    if search_str.chomp =~ /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/
      options[:search] = search_str.chomp
    else
      begin
        ip = Resolv.getaddress(search_str.chomp) # Resolve Host Domain to IP
        options[:search] = ip
      rescue Resolv::ResolvError => e
        cls
        banner
        puts
        puts "Unable to Resolve Host to IP".light_red + "!".white
	puts
        puts opts
        puts
        exit 69;
      end
    end
  end
  opts.on('-S', '--source SOURCE', "\n\tSet Exploit Source: exploitdb or metasploit".white) do |source|
    sources=["metasploit", "exploitdb"]
    if sources.include?(source.downcase.chomp)
      options[:source] = source.downcase.chomp
    else
      cls
      banner
      puts
      puts "Invalid Search Source Requested".light_red + "!".white
      puts "\t=> #{source}".light_red
      puts
      puts opts
      puts
      exit 69;
    end
  end
  opts.on('-x', '--exploit-search STRING', "\n\tShodan Exploit Search for String (requires -S)".white) do |search_str|
    options[:method] = 4 # 1=> Normal, 2=> IP, 3=> Quick, 4=>Exploit Search, 5=>Exploit Download
    options[:search] = search_str.chomp
  end
  opts.on('-d', '--download-id ID', "\n\tDownload Exploit by Exploit ID (requires -S)".white) do |search_str|
    options[:method] = 5 # 1=> Normal, 2=> IP, 3=> Quick, 4=>Exploit-DB Search, 5=>Exploit-DB Download
    options[:search] = search_str.chomp
  end
  opts.on('-H', '--help', "\n\tHelp Menu".white) do 
    cls
    banner
    puts
    puts opts
    puts
    exit 69;
  end
end
begin
  foo = ARGV[0] || ARGV[0] = "-H"
  optparse.parse!
  mandatory = [:method,:search]
  missing = mandatory.select{ |param| options[param].nil? }
  if not missing.empty?
    cls
    banner
    puts
    puts "Missing options: ".red + " #{missing.join(', ')}".white  
    puts optparse
    exit 666;
  end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument, OptionParser::AmbiguousOption
  cls
  banner
  puts
  puts $!.to_s.red
  puts
  puts optparse
  puts
  exit 666;   
end

banner
shodan = ShodanAPI.new(APIKEY)
if shodan.connected?
  # Display Basic API Key Info
  shodan.info
  puts

  # Create Results Dir if it doesnt exist
  Dir.mkdir(RESULTS) unless File.exists?(RESULTS) and File.directory?(RESULTS)

  # Now run as requested....
  case options[:method].to_i
  when 1
    results = shodan.search(options[:search].to_s)
    if not results.nil?
      puts "Shodan Search".light_green + ": #{options[:search].to_s}".white
      f=File.open(RESULTS + "shodan_search_results.txt", 'w+')
      f.puts "Shodan Search: #{options[:search].to_s}"
      puts "Total Results Found".light_green + ": #{results['total']}".white
      f.puts "Total Results Found: #{results['total']}"
      results['countries'].each do |country|
        puts "  #{country['name']}".light_green + ": #{country['count']}".white
        f.puts "  #{country['name']}: #{country['count']}"
      end
      puts
      f.puts
      results['matches'].each do |host|
        puts "Host IP".light_green + ": #{host['ip']}".white
        f.puts "Host IP: #{host['ip']}"
        puts "#{host['data']}".white
        f.puts host['data']
      end
      f.puts
      f.close
    else
      puts "No Results Found for ".light_red + "#{string}".white + " via Shodan Search".light_red + "!".white
    end
    puts
  when 2
    # Check Host Results
    results = shodan.host(options[:search].to_s)
    if not results.nil?
      f=File.open(RESULTS + "shodan_host_search_results.txt", 'w+')
      puts "Host IP".light_green + ": #{results['ip']}".white unless results['ip'].nil?
      f.puts "Host IP: #{results['ip']}" unless results['ip'].nil?
      puts "ISP".light_green + ": #{results['data'][0]['isp']}".white unless results['data'][0]['isp'].nil?
      f.puts "ISP: #{results['data'][0]['isp']}" unless results['data'][0]['isp'].nil?
      puts "Hostname(s)".light_green + ": #{results['hostnames'].join(',')}".white unless results['hostnames'].empty?
      f.puts "Hostname(s): #{results['hostnames'].join(',')}" unless results['hostnames'].empty?
      puts "Host OS".light_green + ": #{results['os']}".white unless results['os'].nil?
      f.puts "Host OS: #{results['os']}" unless results['os'].nil?
      puts "Country".light_green + ": #{results['country_name']}".white unless results['country_name'].nil?
      f.puts "Country: #{results['country_name']}" unless results['country_name'].nil?
      puts "City".light_green + ": #{results['city']}".white unless results['city'].nil?
      f.puts "City: #{results['city']}" unless results['city'].nil?
      puts "Longitude".light_green + ": #{results['longitude']}".white unless results['longitude'].nil? or results['longitude'].nil?
      f.puts "Longitude: #{results['longitude']}" unless results['longitude'].nil? or results['longitude'].nil?
      puts "Latitude".light_green + ": #{results['latitude']}".white unless results['longitude'].nil? or results['longitude'].nil?
      f.puts "Latitude: #{results['latitude']}" unless results['longitude'].nil? or results['longitude'].nil?
      f.puts
      puts
      # We need to split and re-pair up the ports & banners as ports comes after banners in results iteration
      ban=nil
      port_banners={}
      results['data'][0].each do |k, v|
        if k == 'port'
          port=v
          if not ban.nil?
            port_banners.store(port, ban) # store them in hash so we pair them up properly
            ban=nil
          end
        elsif k == 'banner'
          ban=v
        end
      end
      # Now we can display them in proper pairs
      port_banners.each do |port, ban|
        puts "Port".light_green + ": #{port}".white
        f.puts "Port: #{port}"
        puts "Banner".light_green + ": \n#{ban}".white
        f.puts "Banner: \n#{ban}"
      end
      f.puts
      f.close
    else
      puts "No results found for host".light_red + "!".white
    end
    puts
  when 3
    # Perform Quick Shodan Search
    string = options[:search].to_s
    ips = shodan.quick_search(string)
    if not ips.nil?
      puts "Shodan Search".light_green + ": #{string}".white
      puts "Total Results".light_green + ": #{ips.size}".white
      puts "IP Addresses Returned".light_green + ": ".white
      f=File.open(RESULTS + 'quick_search-ips.lst', 'w+')
      ips.each {|x| puts "  #{x}".white; f.puts x }
      f.close
    else
      puts "No Results Found for ".light_red + "#{string}".white + " via Shodan Quick Search".light_red + "!".white
    end
    puts
  when 4
    # Search for Exploits
    string = options[:search].to_s
    source = options[:source].to_s
    results = shodan.sploit_search(string, source)
    if not results.nil?
      f=File.open(RESULTS + "shodan_#{source}_search_results.txt", 'w+')
      puts "Shodan Exploit Search".light_green + ": #{string}".white
      f.puts "Shodan Exploit Search: #{string}"
      results.each do |id, stuff|
        puts "ID".light_green + ": #{id}".white unless id.nil?
        f.puts "ID: #{id}" unless id.nil?
        stuff.each do |link, desc|
          puts "View".light_green + ": #{link.sub('http://www.metasploit.com/', 'http://www.rapid7.com/db/')}".white unless link.nil?
          f.puts "View: #{link.sub('http://www.metasploit.com/', 'http://www.rapid7.com/db/')}" unless link.nil?
          if not link.nil? and source.downcase == 'metasploit'
            puts "Github Link".light_green + ": https://raw.github.com/rapid7/metasploit-framework/master/#{link.sub('http://www.metasploit.com/', '').sub('/exploit/', '/exploits/').sub(/\/$/, '')}.rb".white
            f.puts "Github Link: https://raw.github.com/rapid7/metasploit-framework/master/#{link.sub('http://www.metasploit.com/', '').sub('/exploit/', '/exploits/').sub(/\/$/, '')}.rb"
          end
          puts "Exploit Description".light_green + ": \n#{desc}".white unless desc.nil?
          f.puts "Exploit Description: \n#{desc}" unless desc.nil?
          f.puts
          puts
        end
      end
      f.close
    else
      puts "No Results Found for ".light_red + "#{string}".white + " via Shodan Exploit Search".light_red + "!".white
    end
    puts
  when 5
    # Now download one of the exploits you found....
    id=options[:search].to_s
    source = options[:source].to_s
    results = shodan.sploit_download(id, source)
    if not results.nil?
      downloads = RESULTS + 'downloads/'
      Dir.mkdir(downloads) unless File.exists?(downloads) and File.directory?(downloads)
      f=File.open(downloads + "#{source}-#{id}.code", 'w+')
      results.each do |k, v|
        if k == 'Exploit'
          puts "Saved to".light_green + ": #{downloads}#{source}-#{id}.code".white
          puts "#{k}".light_green + ": \n#{v}".white
          f.puts v
        else
          puts "#{k}".light_green + ": #{v}".white
        end
      end
      f.close
    else
      puts "No Download Results Found for ID".light_red + "#: #{id}".white
    end
  end 
else
  exit 666;
end
#EOF
