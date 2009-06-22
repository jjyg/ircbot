#!/usr/bin/ruby

# ruby irc bot
# (c) 2008 Y. Guillot
# Published under the terms of WtfPLv2

CONF = {
	:server => 'irc.lol.com',
	:chan => '#koolz',
	:nick => '`bot',
	:admin_nick => 'bob',
	:admin_re => /^bob!~marcel@roots.org$/,
}

require 'socket'
begin ; require 'libhttpclient' ; rescue LoadError end

class IrcClient
	attr_accessor :host, :port, :nick, :uhost, :chan
	def initialize
		@host = CONF[:server]
		@port = CONF[:port] || 6667
		@chan = CONF[:chan]
		@nick = CONF[:nick]
		@uhost= CONF[:uhost] || 'bot bot bot :da bot'
	end

	def connect
		@sock = TCPSocket.open @host, @port
		send "user #@uhost", "nick #@nick"
		loop do
			r, w, e = IO.select([@sock])
			l = @sock.gets.chomp
			puts l if $VERBOSE
			case l.split[1]
			when '376'; break
			when '433'	# nick taken
				@nick += rand(1000).to_s
				send "nick #@nick"
			end
		end
		send "join #@chan"
	end

	def run
		connect
		loop { run_loop }
	end

	def run_loop
		r, w, e = IO.select [@sock], nil, nil, 0.5
		if not r
			handle_timeout
		elsif r.include? @sock
			handle_sock @sock.gets.chomp
		end
	end

	def send(*l)
		l.each { |ll|
			puts "#{Time.now.strftime '%H:%M'} > #{ll}" if $VERBOSE
			@sock.write ll.chomp << "\r\n"
		}
	end

	def pm(l, dst=@chan)
		l.each { |l|
			l.chomp!
			send "PRIVMSG #{dst} :#{l.empty? ? ' ' : l}"
		}
	end

	def handle_sock l
		begin
			puts "#{Time.now.strftime '%H:%M'} #{l}" if $VERBOSE
			case l
			when /^:(\S*) PRIVMSG (\S*) :(.*)/i
				handle_privmsg $1, $2, $3
				handle_misc(l)
			when /^ping (.*)/i
				send "pong #$1"
			else handle_misc(l)
			end
		rescue Object
			pm "#{$!.class} #{$!.message} #{$!.backtrace.first}", CONF[:admin_nick]
			sleep 2
		end
	end

	def handle_timeout
	end

	def handle_misc(l)
		case l
		when /^:(\S+)!\S+ (part|quit|nick|kick|join|privmsg #\S*) :?(.*?)$/i
			who, what, arg = $1.downcase, $2, $3
			what = {'part' => 'leaving', 'quit' => 'quitting:', 'nick' => 'changing nick to',
				'kick' => 'kicked', 'join' => 'joining', 'privmsg' => 'saying' }[what.downcase.split.first]
			seen = {}
			File.read('seen.txt').each { |l|
				l =~ /^(\d+) (\S+) (.*)/
					seen[$2.downcase] = [$1.to_i, $3]
			} rescue nil
			seen[who] = [Time.now.to_i, "#{what.downcase} #{arg}"]
			File.open('seen.tmp', 'w') { |fd| fd.puts seen.map { |k, (d, t)| "#{d} #{k} #{t}" }.sort }
			File.rename('seen.tmp', 'seen.txt')
		end
	end

	def repl(l) pm l, @repltarget end

	def handle_privmsg(from, to, msg)
		@repltarget = to
		@repltarget = from.sub(/!.*/, '') if to[0] != ?# and to[0] != ?&

		if from =~ CONF[:admin_re] and to == @nick
			case msg
			when '!reload'
				repl 'ok'
				load $0
			when '!quit'
				send 'quit :requested'
			when /^!quit .*/
				send "quit :#$1"
			when /^!raw (.*)/
				send $1
			end
		end

		return if to.downcase != @chan

		if msg =~ /\/\S*\//
			msg.scan(/\S+\/\S*\/\S*/) { |u| File.open('urls.txt', 'a') { |fd| fd.puts u } if u.include? '.' }
		end

		case msg
		when /^!(\w+)quote(.*)/
			cmd_quote $1, $2, from
		when /^!urls(.*)/
			cmd_url $1
		when /^!seen (\S+)/
			tg = $1.downcase
			seen = false
			File.read('seen.txt').each { |l|
				l =~ /^(\d+) (\S+) (.*)/
				d, w, t = $1, $2, $3
				next if w.downcase != tg
				seen = true
				dt = format_deltat(Time.now - Time.at(d.to_i))
				repl "#{w} was last seen #{dt} ago #{t}"
				tg = $1.downcase if t =~ /^nick :?(.*)/i        # recurse
			} rescue nil
			repl 'nope' if not seen
		when /^!tr(?:anslate)?(.*)/
			return if not defined? HttpClient
			case $1
			when / (\w\w|auto)( \w\w)? (.*)/
				l1, l2, mg = $1, $2, $3
				l1, l2 = 'fr', l1 if not l2
				l2.strip!
				l1 = 'zh-CN' if l1 == 'cn'
				l2 = 'zh-CN' if l2 == 'cn'
				h = HttpClient.new('www.google.com')
				p = h.get("/uds/Gtranslate?callback=cb&context=22&langpair=#{l1}%7C#{l2}&key=notsupplied&v=1.0&q=" + HttpServer.urlenc(mg))
				if p.status == 200 and transl = p.content[/\{"translatedText":"(.*)"\}, /, 1]
					transl.gsub!(/\\u00(..)/) { $1.hex.chr }
					transl = HttpServer.htmlentitiesdec(transl)
					repl transl
				end
			end
		when /^!search (.*)/
			return if not defined? HttpClient
			term = $1
			pg = HttpClient.new("http://www.google.com/").get("/search?q=#{HttpServer.urlenc term}")
			if pg.status == 200
				stat = 0
				url = nil
				pg.parse.delete_if { |t|
					case t.type
					when 'Comment'; stat += 1 if t['content'] == '<!--m-->' or t['content'] == '<!--n-->'
					when 'a'; url ||= t['href'] if stat == 1
					end
					stat != 1
				}
				url ||= 'notfound'
				pg.parse[0].type = 'body' if not pg.parse.empty?        # get_text needs <body>
				repl "#{url} #{pg.get_text.split.join(' ')[0..400]}"
			end
		when /^!\w/
			strs = <<EOS.to_a
you talking to me ?
qui me parle?
does not compute
mmh mh...
EOS
			repl strs[rand(strs.length)] if rand(4) == 1
		end
	end

	def format_deltat(delta)
		delta = delta.to_i
		str = []
		[[365*24*60*60, 'y'], [30*24*60*60, 'm'], [24*60*60, 'd'], [60*60, 'h'], [60, 'm'], [1, 's']].each { |mul, let|
			if delta > mul
				str << "#{delta/mul}#{let}" if str.length < 3
				delta %= mul
			end
		}
		str.join
	end

	def cmd_url(arg)
		u = File.read('urls.txt').to_a.uniq
		case arg.strip
		when /^(\d*)$/
			nr = $1.empty? ? 4 : $1.to_i
			nr = [nr, 10, u.length].min
		when /(?:search )?(.*)/
			u = u.grep(/#$1/i)
			u << 'no match' if u.empty?
			nr = [4, u.length].min
		end
		nr.times { |i| repl "#{u[-i-1]}" }
	end

	class Quote
		attr_accessor :date, :owner, :text

		def initialize(date, owner, text)
			@date = date.to_i
			@owner = owner
			@text = text
		end

		def self.parse(str)
			if str =~ /^(\d+) (\S+) (.*)/
				Quote.new($1.to_i, $2, $3)
			else
				Quote.new(0, '?', str.chomp)
			end
		end

		def store; "#@date #@owner #@text" end

		def to_s ; @text end
	end

	def cmd_quote(type, arg, owner)
		q = (File.read('quotes.txt').map { |l| Quote.parse l } rescue [])
		arg.strip!
		parseint = proc {
			if not arg.empty? and (nr = Integer(arg) rescue nil) and nr < q.length and nr >= 0
				nr
			end
		}

		case type
		when 'add'
			quote = Quote.new(Time.now, owner, arg.gsub(/<(\S+?)>/, "\00303<\\1>\003"))
			File.open('quotes.txt', 'a') { |fd| fd.puts quote.store }
			repl "added quote #{q.length}"
		when 'get', 'topic'
			case arg
			when /^\d+$/; nr = parseint[]
			when ''; nr = rand(q.length)
			else
				if arg =~ /^(\d+)\s+(.*)/
					nr = $1.to_i
					arg = $2
				end
				subq = q.find_all { |qq| qq.text =~ /#{arg}/i }
				nr = q.index(subq[nr || rand(subq.length)])
			end
			if not nr
				repl "quote not found"
				return
			end
			msg = "\00307(#{nr})\003 #{q[nr]}"
			case type
			when 'get'; repl msg
			when 'topic'; send "topic #@repltarget :#{msg}"
			end
		when 'count'
			arg = arg[1..-1].strip if arg =~ /^s( .*)?$/
			subq = q.find_all { |qq| qq.text =~ /#{arg}/i }
			repl "#{subq.length} quotes"
		else
			return if not nr = parseint[]
			case type
			when 'del'
				qq = q.delete_at(nr)
				File.open('quotes.tmp', 'w') { |fd| fd.puts q.map { |qt| qt.store } }
				File.rename 'quotes.tmp', 'quotes.txt'
				repl "deleted (#{nr}) #{qq}"
			when 'who'
				repl "quote #{nr} by #{q[nr].owner}"
			when 'when'
				repl "quote #{nr} added #{Time.at(q[nr].date).strftime('%d/%m/%Y %H:%M:%S')}"
			end
		end
	end
end

if __FILE__ == $0 && !defined? $original
	$original = true	# !reload hack
	if not $VERBOSE
		$stdin.close rescue nil
		$stdout.close rescue nil
		$stderr.close rescue nil
		exit if fork
		while chld = fork
			sleep(1200)
			loop { Process.waitpid(chld) rescue break }
			load __FILE__
		end
	end
	IrcClient.new.run
end
