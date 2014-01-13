ShodanAPI
=========

This is the Shodan API Class &amp; Search tool that I wrote in Ruby since their default API wasn't working for me. You can either drop the API class in and use how you like or you can  just use or tweak the tool I made iwth it. Open to questions, suggestions and general feedback...


Using ShodanAPI Class:
----------------------
```
# API Key Goes Here:
dakey='pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM'

# Initialize and create our API object
shodan = ShodanAPI.new(dakey)

if shodan.connected?
  # Display Basic API Key Info
  shodan.info
  puts

  # Check Results Count for Search
  string = 'cisco-ios'
  count = shodan.count(string)
  if not count.nil?
      puts "Shodan Search: #{string}"
      puts "Total Results: #{count}"
  else
    puts "Unable to get results count!"
  end
  puts

  # Check Host Results
  results = shodan.host('217.140.75.46')
  if not results.nil?
    puts "Host IP: #{results['ip']}" unless results['ip'].nil?
    puts "ISP: #{results['data'][0]['isp']}" unless results['data'][0]['isp'].nil?
    puts "Hostname(s): #{results['hostnames'].join(',')}" unless results['hostnames'].empty?
    puts "Host OS: #{results['os']}" unless results['os'].nil?
    puts "Country: #{results['country_name']}" unless results['country_name'].nil?
    puts "City: #{results['city']}" unless results['city'].nil?
    puts "Longitude: #{results['longitude']}" unless results['longitude'].nil? or results['longitude'].nil?
    puts "Latitude: #{results['latitude']}" unless results['longitude'].nil? or results['longitude'].nil?
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
      puts "Port: #{port}"
      puts "Banner: \n#{ban}"
    end
  else
    puts "No results found for host!"
  end
  puts

  # Perform Quick Shodan Search
  string = 'cisco-ios'
  ips = shodan.quick_search(string)
  if not ips.nil?
    puts "Shodan Search: #{string}"
    puts "Total Results: #{ips.size}"
    puts "IP Addresses Returned: "
    ips.each {|x| puts "  #{x}" }
  else
    puts "No Results Found for #{string} via Shodan Quick Search!"
  end
  puts

  # Perform Full Shodan Search
  string = 'IIS/5.1'
  results = shodan.search(string)
  if not results.nil?
    puts "Shodan Search: #{string}"
    puts "Total Results Found: #{results['total']}"
    results['countries'].each do |country|
      puts "  #{country['name']}: #{country['count']}"
    end
    puts
    results['matches'].each do |host|
      puts "Host IP: #{host['ip']}"
      puts "#{host['data']}"
    end
  else
    puts "No Results Found for #{string} via Shodan Search!"
  end
  puts

  # Search for Exploits
  string = 'udev'
  source = 'metasploit' # Try with 'exploitdb' or 'metasploit'
  results = shodan.sploit_search(string, source)
  if not results.nil?
    puts "Shodan Exploit Search: #{string}"
    results.each do |id, stuff|
      puts "ID: #{id}" unless id.nil?
      stuff.each do |link, desc|
        puts "View: #{link.sub('http://www.metasploit.com/', 'http://www.rapid7.com/db/')}" unless link.nil?
        if not link.nil? and source.downcase == 'metasploit'
          puts "Github Link: https://raw.github.com/rapid7/metasploit-framework/master/#{link.sub('http://www.metasploit.com/', '').sub('/exploit/', '/exploits/').sub(/\/$/, '')}.rb"
        end
        puts "Exploit Description: \n#{desc}" unless desc.nil?
        puts
      end
    end
  else
    puts "No Results Found for #{string} via Shodan Exploit Search!"
  end
  puts

  # Now download one of the exploits you found....
  id='modules/exploit/linux/local/udev_netlink' # 16099 for exploitdb, modules/exploit/linux/local/udev_netlink for metasploit
  results = shodan.sploit_download(id, source)
  if not results.nil?
    results.each do |k, v|
      if k == 'Exploit'
        puts "#{k}: \n#{v}"
      else
        puts "#{k}: #{v}"
      end
    end
  else
    puts "No Download Results Found for ID: #{id}!"
  end
else
  exit 666;
end```
