#!/usr/bin/ruby

# ruby irc bot
# (c) 2008-2009 Y. Guillot
# Published under the terms of WtfPLv2

require 'socket'
require 'time'
require 'timeout'
require 'utf8decode'
begin ; require 'libhttpclient' ; rescue LoadError ; end
begin ; require 'openssl' ; rescue LoadError ; end


# standard plugins

class Admin
	def initialize(irc)
		irc.plugin_admin << self
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when '!reload'
			irc.repl 'ok'
			load __FILE__
		when /^!reload (.*)/
			f = $1
			if File.exist?(f)
				load f
				irc.repl 'ok'
			else
				irc.repl 'ENOENT'
			end
		when '!quit'
			irc.send 'quit :requested'
		when /^!quit (.*)/
			irc.send "quit :#$1"
		when /^!raw (.*)/
			irc.send $1
		when /^!plugin (load|unload|reload|list)(.*)/
			act = $1
			pl = Object.const_get($2.strip) rescue nil
			if act == 'list'
				irc.repl irc.plugins.flatten.uniq.map { |plug| plug.class.name }.sort.join(' ')
			elsif not pl
				irc.repl 'unknown plugin'
			elsif pl == self.class and act == 'unload'
				irc.repl 'can\'t do that, Dave'
			else
				irc.plugins.each { |l| l.delete_if { |plug| plug.kind_of? pl } }
				if act == 'load' or act == 'reload'
					pl.new(irc)
				end
				irc.repl 'ok'
			end
		end
	end

	def help ; "Admin commands - !reload | !quit | !raw <raw irc>" end
end

class Ruby
	def initialize(irc)
		irc.plugin_admin << self
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when /^!ruby (.*)/
			eval $1
		end
	end

	def help ; "Execute arbitrary ruby commands - !ruby irc.repl 'foo'" end
end

class GoogleSearch
	def initialize(irc)
		irc.plugin_msg << self
	end
	
	def handle_msg(irc, msg, from, to)
		case msg
		when /^!(?:search|google) +(.*)/
			return if not defined? HttpClient
			term = $1
			pg = HttpClient.open("http://www.google.com/") { |h| h.get("/search?q=#{HttpServer.urlenc term}") }
			if pg.status == 200
				stat = 0
				url = nil
				calc = nil
				pg.parse.delete_if { |t|
					case t.type
					when 'Comment'; stat += 1 if t['content'] == 'm' or t['content'] == 'n'
					when 'a'; url ||= t['href'] if stat == 1
					when 'h2'; calc = true if t['class'] == 'r'
					when 'String'; if calc ; irc.repl t['content'] ; calc = nil ; end
					end
					stat != 1
				}
				url ||= 'notfound'
				pg.parse[0].type = 'body' if not pg.parse.empty?        # get_text needs <body>
				irc.repl "#{url} #{pg.get_text.split.join(' ')[0..400]}"
			end
		end
	end

	def help ; "Shows the first search result from google - !search <search token>" end
end

class GoogleTranslate
	def initialize(irc)
		irc.plugin_msg << self
	end

	def handle_msg(irc, msg, from, to)
		return if not defined? HttpClient
		case msg
		when /^!tr(?:anslate)? +(\w\w|auto)( +\w\w)? (.*)/
			l1, l2, msg = $1, $2, $3
			l1, l2 = 'fr', l1 if not l2
			l2.strip!
			l1 = 'zh-CN' if l1 == 'cn'
			l2 = 'zh-CN' if l2 == 'cn'
			if transl = translate(l1, l2, msg)
				irc.repl transl
			end
		else
			if false
				transl = translate('fr', 'en', msg)
				transl.gsub!(/(\W)h/i, '\1.')
				transl.gsub!(/th/, 'z')
				transl.gsub!(/Th/, 'Z')
				irc.pm "<#{from.sub(/!.*/, '').sub(/(.)/, '\1-')}> #{transl}", "#fr2en"
			end
		end
	end

	def translate(l1, l2, msg)
		HttpClient.open('www.google.com') { |h|
			p = h.get("/uds/Gtranslate?callback=cb&context=22&langpair=#{l1}%7C#{l2}&key=notsupplied&v=1.0&q=" + HttpServer.urlenc(msg))
			if p.status == 200 and transl = p.content[/\{"translatedText":"(.*)"\}, /, 1]
				transl.gsub!(/\\u00(..)/) { $1.hex.chr }
				HttpServer.htmlentitiesdec(transl)
			end
		}
	end

	def help ; "Translate sentences using Google Translate - !tr <in> <out> <phrase> eg '!tr fr en Bonjour'" end
end

class RSS
	def initialize(irc)
		irc.plugin_idle << self
		irc.plugin_msg << self
	end

	def handle_idle(irc)
		t = Time.now
		@poll_rss ||= t
		if t > @poll_rss
			begin
				Timeout.timeout(40) { poll_rss(irc) }
			rescue Timeout::Error
			end
			@poll_rss = Time.now + (CONF[:rss_poll_delay] || 120) + rand(30)
		end
	rescue Object
		irc.pm "#{$!.class} #{$!.message} #{$!.backtrace.first}", CONF[:admin_nick]
		sleep 2
	end


	def poll_rss(irc)
		return if not File.exist? 'rss.txt'

		@cur_rss ||= -1

		rsses = File.readlines('rss.txt').map { |l| l.chomp } - ['']
		return if rsses.empty?

		@cur_rss += 1
		@cur_rss %= rsses.length
		name, url, lasttitle = rsses[@cur_rss].split(/\s+/, 3)

		return if not url
		rss = parsehtml HttpClient.open(url) { |h| h.get(url) }.content

		# check last post: content of first <title> in <item> / <entry>
		initem = intitle = false
		title = nil
		rss.each { |tag|
			case tag.type
			when 'entry', 'item'; initem = true
			when 'title'; intitle = true if initem
			when '/title'; intitle = false
			when 'String', 'Cdata'; next if not intitle ; title = tag['content'].gsub(/\s+/, ' ') ; break
			end
		}
		return if not title or title == lasttitle

		# update last title
		rsses[@cur_rss] = [name, url, title].join(' ')
		File.open('rss.txt.tmp', 'w') { |fd| fd.puts rsses }
		File.rename('rss.txt.tmp', 'rss.txt')

		irc.pm "rss: #{name}: #{title}", irc.chan
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when '!rss'
			rsses = File.readlines('rss.txt')
			irc.repl rsses.map { |rss| rss.split[0] }.join(' ')
		when /^!rss (.*)/
			name, url = $1.split
			url, name = name, url if name.to_s.include? '/' and not url.to_s.include? '/'
			if url and url.include? '/'
				url = "http://#{url}" if not url.include? '://'
				File.open('rss.txt', 'a') { |fd| fd.puts "#{name} #{url}" }
				irc.repl 'ok'
			elsif not rss = File.readlines('rss.txt').find { |l| l.split[0] == name }
				irc.repl 'unknown'
			else
				irc.repl rss.chomp
			end
		when /^!norss (.*)/
			name = $1
			rsses = File.readlines('rss.txt')
			if rss = rsses.find { |l_| l_.split[0] == name }
				rsses.delete rss
				File.open('rss.txt.tmp', 'w') { |fd| fd.puts rsses }
				File.rename('rss.txt.tmp', 'rss.txt')
				irc.repl 'ok'
			else
				irc.repl 'unknown'
			end
		end
	rescue
	end


	def help ; "RSS to IRC - !rss <shortname> <url> | !norss <shortname>" end
end

class Twitter
	def initialize(irc)
		irc.plugin_idle << self
		irc.plugin_msg << self
	end

	def handle_idle(irc)
		t = Time.now
		@poll_twitter_timeout ||= t
		if t > @poll_twitter_timeout
			begin
				Timeout.timeout(40) { poll_twitter(irc) }
			rescue Timeout::Error
			end
			@poll_twitter_timeout = Time.now + (CONF[:twitter_poll_delay] || 120) + rand(30)
		end
	rescue Object
		irc.pm "#{$!.class} #{$!.message} #{$!.backtrace.first}", CONF[:admin_nick]
		sleep 2
	end


	def twit_decode_html(str)
		HttpServer.htmlentitiesdec(HttpServer.htmlentitiesdec(str)).gsub(/&#(x?\d+);/) {
			# utf-8 encode
			v = ($1[0] == ?x) ? $1[1..-1].to_i(16) : $1.to_i
			next v.chr if v <= 255
			next 'lol' if v > 0x1fffff
			raw = ''
			limit = 0x3f
			while v > limit
				raw << (0x80 | (v & 0x3f))
				v >>= 6
				limit >>= 1
			end
			len = raw.length+1
			raw << (((0xff << (8-len)) & 0xff) | v)
			raw.reverse!
		}
	end

	def date2delay(date)
		dt = (Time.now - date).to_i
		if dt > 3600*36;  " il y a #{dt/3600/24}j"
		elsif dt > 3600;  " il y a #{dt/3600}h#{(dt%3600)/60}"
		elsif dt > 15*60; " il y a #{dt/60}mn"
		elsif dt > 2*60;  " il y a #{dt/60}mn#{dt%60}"
		end
	end

	def account
		CONF[:twitter_account]
	end

	def http_post(url, pd={})
		pass = CONF[:twitter_password] || File.read(CONF[:twitter_password_file]).chomp
		HttpClient.open("http://#{account}:#{pass}@twitter.com/") { |h| h.post(url, pd) }
	end

	def http_get(url)
		pass = CONF[:twitter_password] || File.read(CONF[:twitter_password_file]).chomp
		HttpClient.open("http://#{account}:#{pass}@twitter.com/") { |h| h.get(url) }
	end

	def poll_twitter(irc)
		rss = parsehtml http_get("/statuses/friends_timeline/#{account}.rss").content, true
		lastag = nil
		rss.delete_if { |tag|
			if tag.type == 'String'; lastag['str'] = twit_decode_html(tag['content']) ; true
			elsif lastag and tag.type == '/'+lastag.type; lastag = nil; true
			else lastag = tag; false
			end
		}

		done = 0
		@lasttweetseen ||= Time.now - 24*3600
		good = date = text = nil
		rss.reverse_each { |tag|
			val = tag['str']
			case tag.type
			when 'link';        good = (val and !val.include?("/#{account}/"))
			when 'pubdate';     date = Time.parse(val)
			when 'description'; text = val
			when 'item'
				if good and date > @lasttweetseen and done <= 3
					@lasttweetseen = date
					irc.pm "tweet from #{text}#{date2delay(date)}", irc.chan
					done += 1
				end
			end
		}

		rpl = parsehtml http_get("/statuses/replies.xml").content, true
		lastag = nil
		rpl.delete_if { |tag|
			if tag.type == 'String'; lastag['str'] = twit_decode_html(tag['content']) ; true
			elsif lastag and tag.type == '/'+lastag.type; lastag = nil; true
			else lastag = tag; false
			end
		}

		@lastreplseen ||= Time.now - 24*3600
		date = text = user = fol = nil
		rpl.reverse_each { |tag|
			val = tag['str']
			case tag.type
			when 'screen_name'; user = val
			when 'following';   fol = val
			when 'text';        text = val
			when 'created_at';  date = Time.parse(val)
			when 'status'
				if fol != 'true' and date > @lastreplseen and done <= 3
					@lastreplseen = date
					irc.pm "tweet from #{user}: #{text}#{date2delay(date)}", irc.chan
					done += 1
				end
			end
		}
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when /^!tw(?:ee|i)t(?:t|ter)? (.*)/
			msg = $1
			msg = UnUTF8.new(msg).to_s
			msg = HttpServer.htmlentitiesenc(msg)
			pg = http_post('/statuses/update.xml', 'status'=>msg, 'source'=>'twitterircgateway')
			irc.repl(pg.status == 200 ? "http://twitter.com/#{account}" : 'fail')
		when /^!follow (.*)/
			pg = http_post("/friendships/create/#$1.xml")
			irc.repl(pg.status == 200 ? 'ok' : 'fail')
		when /^!nofollow (.*)/
			pg = http_post("/friendships/destroy/#$1.xml")
			irc.repl(pg.status == 200 ? 'ok' : 'fail')
		end
	end

	def help ; "Twitter to irc - !twit <publish_msg> | !follow <account> | !nofollow <account>" end
end

class Quote
	def initialize(irc)
		irc.plugin_msg << self
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

	def handle_msg(irc, msg, from, to)
		return if msg !~ /^!(\w*)quote(.*)/
		type = $1
		arg = $2
		owner = from

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
			irc.repl "added quote #{q.length}"
		when '', 'get', 'topic'
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
				irc.repl "quote not found"
				return
			end
			msg = "\00307(#{nr})\003 #{q[nr]}"
			case type
			when 'topic'; irc.send "topic #{irc.repltarget} :#{msg}"
			else irc.repl msg
			end
		when 'count'
			arg = arg[1..-1].strip if arg =~ /^s( .*)?$/
			subq = q.find_all { |qq| qq.text =~ /#{arg}/i }
			irc.repl "#{subq.length} quotes"
		else
			return if not nr = parseint[]
			case type
			when 'del'
				qq = q.delete_at(nr)
				File.open('quotes.tmp', 'w') { |fd| fd.puts q.map { |qt| qt.store } }
				File.rename 'quotes.tmp', 'quotes.txt'
				irc.repl "deleted (#{nr}) #{qq}"
			when 'who'
				irc.repl "quote #{nr} by #{q[nr].owner}"
			when 'when'
				irc.repl "quote #{nr} added #{Time.at(q[nr].date).strftime('%d/%m/%Y %H:%M:%S')}"
			end
		end
	end

	def help ; "Quote storage & retrieval - !getquote flublu | !addquote <foo> bar | !countquote bla.*bla | !whoquote 412 | !whenquote 412 | !delquote 412 | !topicquote 27" end
end

class Url
	def initialize(irc)
		irc.plugin_msg << self
	end

	def handle_msg(irc, msg, from, to)
		if to.downcase == irc.chan and msg =~ /\/\S*\//
			msg.scan(/\S+\.\S+\/\S*\/\S*|\S+:\/\/\S*/) { |u|
				File.open('urls.txt', 'a') { |fd| fd.puts u }
				begin
					u = u+'/' if u =~ /:\/\/[^\/]*$/
					Timeout.timeout(40) {
						t = nil
						HttpClient.open(u) { |h| h.get(u).parse.each { |e|
							case e.type
							when 'title'; t = ''
							when '/title'; irc.repl t if t; break
							when 'String'; t << e['content'] if t
							end
						} }
					}
				rescue Object
					#irc.pm "#{$!.class} #{$!.message} #{$!.backtrace.first}", CONF[:admin_nick]
				end
			}
		end

		case msg
		when /^!urls?( .*|$)/
			arg = $1.strip
			list = (File.readlines('urls.txt').uniq rescue [])
			case arg.strip
			when /^(\d*)$/
				nr = $1.empty? ? 4 : $1.to_i
				nr = [nr, 10, list.length].min
			when /^(?:search )?(.*)/
				pat = $1.strip
				nr = 4
				nr, pat = $1.to_i, $2.strip if pat =~ /^(\d+) (.*)/
				list = list.grep(/#{pat}/i)
				list << 'no match' if list.empty?
				nr = [nr, 10, list.length].min
			end
			nr.times { |i| irc.repl "#{list[-i-1]}" }
		end
	end

	def help ; "Recall last <n> urls shown on the chan matching a pattern - !url 6 toto.*tutu" end
end

class Seen
	def initialize(irc)
		irc.plugin_misc << self
		irc.plugin_msg << self
	end

	def handle_misc(irc, l)
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

	def handle_msg(irc, msg, from, to)
		case msg
		when /^!seen (\S+)/
			tg = $1.downcase
			seen = false
			File.read('seen.txt').each { |l|
				l =~ /^(\d+) (\S+) (.*)/
				d, w, t = $1, $2, $3
				next if w.downcase != tg
				seen = true
				dt = format_deltat(Time.now - Time.at(d.to_i))
				irc.repl "#{w} was last seen #{dt} ago #{t}"
				tg = $1.downcase if t =~ /^nick :?(.*)/i        # recurse
			} rescue nil
			irc.repl 'nope' if not seen
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

	def help ; "Tells when <who> was last seen acting on IRC - !seen bob" end
end

class Op
	def initialize(irc)
		irc.plugin_misc << self
		irc.plugin_msg << self
		@voiced = false
		@keepop = CONF[:stay_op]
	end

	def handle_misc(irc, l)
		case l
		when /^:\S* MODE ([#&]\S*) (\S+) (.*)/
			chan = $1
			mod = $2
			names = $3.split(' ')
			curop = nil
			chmod = names.map { |n|
				while mod[0] == ?+ or mod[0] == ?-
					curop = mod[0]
					mod = mod[1..-1]
				end
				m = '' << curop << mod[0]
				mod = mod[1..-1]
				[m, n]
			}
			if mm = chmod.find_all { |m, n| m[1] == ?v }.reverse.find { |m, n| n == irc.nick } and mm[0] == '+v'
				@voiced = true
			end
			if mm = chmod.find_all { |m, n| m[1] == ?o }.reverse.find { |m, n| n == irc.nick } and mm[0] == '+o'
				#irc.send "who #{chan}"		# "who +uM blacklist
				irc.send "names #{chan}"
				@optmp = []
			end
		#when /^:\S* 352 #{irc.nick} \S* (\S*) (\S*) \S* (\S*) (\S*) :.*/	# who
		#	ident, host, nick, mode = $1, $2, $3, $4
		#	$blacklist = nick if ident =~ /^~?plop$/i
		# 315 end of who
		when /^:\S* 353 #{irc.nick} \S* [#&]\S* :(.*)/	# names
			(@optmp ||= []).concat $1.split(' ')
		when /^:\S* 366 #{irc.nick} ([#&]\S*) /		# end of names
			chan = $1
			todo = []
			(@optmp ||= []).each { |n|
				m, n = n[0], n[1..-1] if n[0] == ?@ or n[0] == ?+
				#$blacklist ||= 'testic'
				case n
				#when /^#$blacklist/i; todo << ['-v', n] if m == ?+ ; todo << ['-o', n] if m == ?@
				when irc.nick; return if m != ?@
				when /bot/i; todo << ['-o', n] if m == ?@ ; todo << ['+v', n] if m != ?+
				else todo << ['+o', n] if m != ?@
				end
			}
			@optmp.clear
			todo << ['+v', irc.nick] if not @voiced
			@voiced = true
			todo << ['-o', irc.nick] if not @keepop
			max = CONF[:ircd_mode_max] || 4
			until todo.empty?
				t, todo = todo[0, max], todo[max..-1].to_a
				cs = nil
				md = ''
				t.map! { |m, n| m[0] == cs ? md << m[1] : md << m ; cs = m[0] ; n }
				irc.send "mode #{chan} #{md} #{t.join(' ')}"
			end
		end
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when '!op'
			irc.send "mode #{irc.chan} +o #{from.sub(/!.*/, '')}"
		when '!keepop'
			@keepop = true
		when '!nokeepop'
			@keepop = false
			irc.send "mode #{irc.chan} -o #{irc.nick}"
		end
	end

	def help ; "op all chan when bot is oped - also !op / !(no)keepop" end
end

class Help
	def initialize(irc)
		irc.plugin_msg << self
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when '!help'
			irc.repl irc.plugins.flatten.uniq.map { |plug| plug.class.name }.sort.join(' ')
		when /^!help (.*)/
			name = $1.downcase
			pl = irc.plugin_msg.find { |pl| pl.class.name.downcase.include? name }
			if not pl
				irc.repl 'unknown plugin'
			else
				irc.repl pl.help
			end
		end
	end

	def help ; "!help <plugin>" end
end







# the bot itself
class IrcBot
	attr_accessor :host, :port, :nick, :uhost, :chan
	attr_accessor :plugin_misc, :plugin_msg, :plugin_admin, :plugin_idle

	def initialize
		@host = CONF[:ircd]
		@port = CONF[:ircd_port] || 6667
		@chan = CONF[:chan]
		@nick = CONF[:nick]
		@uhost= CONF[:uhost] || 'bot bot bot :da bot'
		@plugin_misc = []
		@plugin_msg = []
		@plugin_admin = []
		@plugin_idle = []

		CONF[:plugins].each { |p| p.new(self) }
	end


	def plugins ; [@plugin_misc, @plugin_msg, @plugin_admin, @plugin_idle] end

	def connect
		@sock = TCPSocket.open @host, @port
                if CONF[:ircd_ssl]
                        @sock = OpenSSL::SSL::SSLSocket.new(@sock, OpenSSL::SSL::SSLContext.new)
                        @sock.sync_close = true
                        @sock.connect
                end
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
		send "join #@chan #{CONF[:chan_pass]}"
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
		l.to_s.each { |l|
			l.chomp!
			send "PRIVMSG #{dst} :#{l.empty? ? ' ' : l}"
		}
	end

	attr_accessor :repltarget
	def repl(l) pm l, @repltarget end

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
		@plugin_idle.each { |p| p.handle_idle(self) }
	end

	def handle_misc(l)
		@plugin_misc.each { |p| p.handle_misc(self, l) }
	end

	def handle_privmsg(from, to, msg)
		@repltarget = to
		@repltarget = from.sub(/!.*/, '') if to[0] != ?# and to[0] != ?&

		if from =~ CONF[:admin_re] and to == @nick
			@plugin_admin.each { |p| p.handle_msg(self, msg, from, to) }
		end

		@plugin_msg.each { |p| p.handle_msg(self, msg, from, to) }
	end

	def self.run_loop
		$stdin.close rescue nil
		$stdout.close rescue nil
		$stderr.close rescue nil
		exit if fork
		while chld = fork
			sleep(1200)
			loop { Process.waitpid(chld) rescue break }
		end
		load __FILE__
		new.run
	end

	def self.start
		return if @@started ||= false	# do not re-launch on !reload
		@@started = true
		if $VERBOSE
			new.run
		else
			run_loop
		end
	end
end


if __FILE__ == $0

# This is what you should put in your bot script

#require 'ircbot'
#<insert custom plugin code here>

# grep 'CONF' in this file to find useful keys to define here
CONF = {
	:ircd => 'irc.lol.com',
	#:ircd_port => 6667,
	#:ircd_ssl => true,
	:chan => '#koolz',
	#:chan_pass => 's3cr3t',
	:nick => '`bot',
	:admin_nick => 'bob',
	:admin_re => /^bob!~marcel@roots.org$/,
	:twitter_account => 'bla',
	:twitter_password => 'blabla',
	:plugins => [Admin, GoogleSearch, GoogleTranslate, RSS, Twitter, Quote, Url, Seen, Op, Help]
}

IrcBot.start

end
