#!/usr/bin/env ruby

# Apache Bot Blocker v0.1
# NeZetiC (nezetic.info)

require 'ipaddr'
require 'time'

LOGFILE = "/var/www/logs/error_log"
BANLOG = "/var/log/banlog"
FCMD = "pfctl -t bruteforce -T add"
EXIP = ["10.0.0.0/8","127.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]
MRATE = "3/10" # n/m : a max of n try in m seconds

class Tail
	# Based on Daniel Berger's class 
	attr_accessor :file, :buffer, :interval

	def initialize(file, buffer=8192, interval=10)
		@file = file
		@buffer = buffer
		@interval = interval

		@fh = File.open(file,"r")
		@fh.sysseek(-1,2) if File.size(@file) > 0
	end

	def read
		begin
			return @fh.sysread(buffer)#.tr("\n","")
		rescue EOFError
			if File.size(@file) > 0 then
				@fh.sysseek(-1,2) 
				sleep interval
				retry
			else
				sleep interval
				return ""
			end
		end
	end

	def close
		@fh.close
	end
end

class Banlist
	attr_reader :rate,:banned
	Cinfo = Struct.new( "Cinfo", :ip, :date, :nbr )
	def initialize(rate="3/10")
		@listip = Array.new
		self.rate = rate
		@banned = Array.new
	end

	def rate=(val)
		@rate = val
		@maxnbr,@maxtime = val.split('/')
		@maxnbr = @maxnbr.to_i
		@maxtime = @maxtime.to_i
	end

	def ban(ip)
		if !self.banned?(ip) then
			@banned.push(ip)
			system(FCMD + " " + ip)
			File.open(BANLOG,"a") do |logfile|
				logfile << "[" + Time.now.to_s + "] [" + ip + "]\n"
				logfile.close
			end
		end
	end

	def banned?(ip)
		len = @banned.length
		len.times do |x|
			i = len - x - 1
			return true if @banned[i] == ip
		end
		false
	end

	def add(ip,date)
		len = @listip.length
		del = 0
		modif = false
		len.times do |x|
			i = len - del - x - 1
			break if i < 0
			if (@listip[i].date + @maxtime) < date then
				#puts "DEL #{@listip[i].ip} #{@listip[i].date}"
				@listip.delete_at(i)
				del = del.next
				redo 
			end
			if @listip[i].ip == ip then
				#puts "MOD #{ip} #{date}" 
				@listip[i].nbr = @listip[i].nbr.next
				self.ban(ip) if (date - @listip[i].date).to_i < @maxtime and  @listip[i].nbr >= @maxnbr
				modif = true
			end
		end
		if !modif and !banned?(ip) then
			#puts "NEW #{ip} #{date}" 
			@listip.push(Cinfo.new(ip,date,1))
		end
	end
end

def ignored? ip
	return true if ip == nil or ip == ""
	nip = IPAddr.new(ip)
	EXIP.size.times do |i|
		net = IPAddr.new(EXIP[i])
		return true if net.include?(nip)
	end
	return false
end

logs = Tail.new(LOGFILE,8192,2)

list = Banlist.new(MRATE)

pid = fork do
	quit=true
	bye = proc {quit=false}
	trap "SIGINT", bye
	trap "TERM", bye

	while (quit)
		news = logs.read
		news.each_line { |line|
			scan = line.scan(/\[[^\]]+\]/)
			if scan.size == 3 then
				date = scan[0][/[^\[\]]+/]
				date = Time.parse(date) if date != nil
				state = scan[1][/[^\[\]]+/]
				ip = scan[2].scan(/[1-9][0-9]*\.[0-9]+\.[0-9]+\.[0-9]+/).to_s
				erreur = line.gsub(/\[.+\]/,"")
			end
			next if ignored?(ip) or state != "error"
			next if !erreur.match("script not found") and !erreur.match("does not exist")
			#puts "<#{state}> <#{ip}> <#{date}> : #{erreur}" 
			list.add(ip,date)
		}
	end

	logs.close

	#print "\nBlacklist (#{list.banned.length}): "
	#list.banned.each { |x| print "\"",x,"\" "}

	#puts "\nBye :)"
end

Process.detach(pid)
