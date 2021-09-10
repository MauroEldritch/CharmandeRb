#!/usr/bin/ruby
#Reads your webserver logs & creates UFW rules to block repeated malicious attempts.
#Mauro Eldritch @ DC5411 - 2021.
require 'colorize'
banner = """                      
          `.-:/+++//-`                            
         `:/+++++++++/:`                          
        `-++++++++++o++/`                         
        sh++++++++/`+m++-                         
      `-s+++++++++s+NNo+/`                        
     ./+++++++++++dmms/+/`                        
     /+++++++++++++oo+++/`                  .     
     -++++++++++++++++++/                ``.o`    
  `.``-/+++++++++++oo+++/`     ```      `//os/.-  
 `.+/:-:++++++++o+oo+++++.`..-://:      .sssoss/  
 `:++++++++////////++++++///++++o/.     `./++sso` 
  `.:++++++:-::::-..-/++++++++++:.`      `..+oss/ 
    `./+++/...-......./+++++++/-`        ...:-+s- 
      `./+:............/++++:.`          .....:/` 
        ``............../+++/`           ``.-::`  
         `..............-++++:`            `:/`   
          ...............+++++.           `-+/    
          `............../++++:`         `-/+-    
         ``-............./++++/.````````-/++/`    
        `://-...........-+++++++/::::://+++/`     
       `/++++/:-.......-/+++++++++++++++//-`      
       .++++++oo+/----:/++++++++///////:-``       
       `-++++oooo:```.++++++++/----...```         
    `.-:/+oooooo+`    .+++o+o+. ````              
   `..-:/+++oooo+-    -//+++//.                   
    ````......``      ...-`:`.`                   
"""
begin
  puts banner.light_red
  if ARGV.length != 2
      puts "[*] Usage: charmande.rb [LOGFILE] [MAX_ERRORS_TOLERATED]\n[*] Example: ´charmande.rb 5´ will create rules to block all hosts with more than 5 non-200 responses.".yellow
      exit 1
  end
  threshold = ARGV[1]
  blacklist = Hash.new(0)   #Repeated offenders.
  logfile = File.readlines(ARGV[0]).map(&:chomp)  #Read logfile.
  puts "[?] Parsing #{ARGV[0]} (#{logfile.count} lines)...".light_blue
  errors = logfile.sort.select { |n| (n.include? "404") } #Grep by 404.
  errors.each {|n| blacklist[n.split()[0]] += 1}  #Count offenses
  offenders = blacklist.select { |n,v| v >= 5 }.count         #Count offenders
  blacklist.sort_by{|k,v| -v}.select { |n,v| v >= threshold.to_i }.each do |n,v| 
    File.write("ufw_rules.sh", "#Blocking #{n} after #{v} tries\nufw deny from #{n}\n", mode: 'a')
    File.write("iptables_rules.sh", "#Blocking #{n} after #{v} tries\niptables -A INPUT -s #{n} -j DROP\n", mode: 'a') 
  end
  puts "[*] Found #{blacklist.count} offenses from #{offenders} malicious addresses.".light_blue
  puts "[*] Run ufw_rules.sh or iptables_run.sh to apply the rules."
rescue => exception
  puts "Charmander has fainted: #{exception}".light_red
end