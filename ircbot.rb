#!/usr/bin/ruby

# ruby irc bot
# (c) 2008-2009 Y. Guillot
# Published under the terms of WtfPLv2

require 'socket'
require 'time'
require 'timeout'
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
		when /^!join (.*)/
			irc.send "join #$1"
		when /^!part (.*)/
			irc.send "part #$1"
		when '!part'
			irc.send "part #{to}"
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
		# uncomment the next line if you want to enable
		# arbitrary ruby code exec from the registered admin
		#case msg
		#when /^!ruby (.*)/; eval $1
		#end
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
				parse_page(irc, pg)
			end
		end
	end

	def parse_page(irc, pg)
		url = nil
		hidden = ires = resultstats = spell = calc = 0
		pre = 1; post = 0
		pg.parse.delete_if { |t|
			pre = 0 if t.type == '/form'
			next true if pre > 0 or post > 0

			case t.type
			when 'div'
				hidden += 1 if hidden > 0 or t['style'] == 'display:none'
				ires += 1 if ires > 0 or t['id'] == 'ires'
				resultstats += 1 if resultstats > 0 or t['id'] == 'resultStats'
			when '/div'
				hidden -= 1 if hidden > 0
				post = 1 if ires == 1
				ires -= 1 if ires > 0
				resultstats -= 1 if resultstats > 0
			when 'h2'
				calc += 1 if t['class'] == 'r'
			when '/h2'
				calc -= 1 if calc > 0
			when 'table'
				hidden += 1 if ires > 0
			when '/table'
				hidden -= 1 if ires > 0
			when 'span'
				spell += 1 if t['class'] == 'spell'
				spell -= 1 if t['class'] == 'spell_orig'
			when '/form'
				pre = 0
			when 'a'
				url ||= t['href'] if ires > 0
			when 'String'
				t['content'] = '(' + t['content'] + ')' if resultstats > 0
				next true if hidden > 0
				irc.repl t['content'] if calc > 0
				next true if ires <= 0 and resultstats <= 0 and spell <= 0
				post = 1 if t['content'] == '...'
			end
			false
		}
		url ||= 'notfound'
		if url =~ /^\/url\?(.*)/ and moo = $1.split('&').map { |s| s.split('=', 2) }.assoc('url')
			url = HttpServer.htmlentitiesdec(moo[1])
		end
		pg.parse[0].type = 'body' if not pg.parse.empty?        # get_text needs <body>
		irc.repl "#{url} #{pg.get_text.split.join(' ')[0..400]}"

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
		HttpClient.open('translate.google.com') { |h|
			p = h.get("/translate_a/t?client=t&sl=#{l1}&tl=#{l2}&text=" + HttpServer.urlenc(msg))
			if p.status == 200
				p.content.force_encoding('binary')[/\["(.*?)",/, 1]
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
			delay = (CONF[:rss_poll_delay] || 1800) + rand(30)
			nrss = (File.exist?('rss.txt') ? File.open('rss.txt', 'rb') { |fd| fd.readlines }.length : 0)
			delay /= [1, [8, nrss].min].max
			@poll_rss = Time.now + delay
		end
	rescue Object
		irc.pm "#{$!.class} #{$!.message} #{$!.backtrace.first}", CONF[:admin_nick]
		sleep 2
	end


	def poll_rss(irc)
		return if not File.exist? 'rss.txt'

		@cur_rss ||= -1

		rsses = File.open('rss.txt', 'rb') { |fd| fd.readlines }.map { |l| l.chomp } - ['']
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

		irc.pm "rss: #{name}  #{title}", irc.chan
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when '!rss'
			rsses = File.open('rss.txt', 'rb') { |fd| fd.readlines }
			irc.repl rsses.map { |rss| rss.split[0] }.join(' ')
		when /^!rss (.*)/
			name, url = $1.split
			url, name = name, url if name.to_s.include? '/' and not url.to_s.include? '/'
			if url and url.include? '/'
				url = "http://#{url}" if not url.include? '://'
				File.open('rss.txt', 'a') { |fd| fd.puts "#{name} #{url}" }
				irc.repl 'ok'
			elsif not rss = File.open('rss.txt', 'rb') { |fd| fd.readlines }.find { |l| l.split[0] == name }
				irc.repl 'unknown'
			else
				irc.repl rss.chomp
			end
		when /^!norss (.*)/
			name = $1
			rsses = File.open('rss.txt', 'rb') { |fd| fd.readlines }
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
		@oauth = {}
		@oauth[:consumer_key], @oauth[:consumer_secret], @oauth[:token], @oauth[:token_secret] =
			File.read(CONF[:twitter_oauth_file]).split
	end

	def account
		CONF[:twitter_account]
	end

	def handle_idle(irc)
		t = Time.now
		@poll_twitter_timeout ||= t
		if t > @poll_twitter_timeout
			begin
				Timeout.timeout(20) { poll_twitter(irc) }
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

	# patch a html parse array, so that <foo>bar</foo>  =>  <foo str="bar" />
	def fold_xml(parse)
		lastag = nil
		parse.delete_if { |tag|
			if lastag and tag.type == 'String'; lastag['str'] = twit_decode_html(tag['content']) ; true
			elsif lastag and tag.type == '/'+lastag.type; lastag = nil; true
			else lastag = tag; false
			end
		}
	end

	def poll_twitter(irc)
		rss = parsehtml oauth_get('/1/statuses/home_timeline.rss').content, true
		fold_xml(rss)

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
					irc.pm "tweet from #{text}#{date2delay(date)}", irc.chan, true
					done += 1
				end
			end
		}

		rpl = parsehtml oauth_get('/1/statuses/mentions.xml').content, true
		fold_xml(rpl)

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
					irc.pm "tweet from #{user}: #{text}#{date2delay(date)}", irc.chan, true
					done += 1
				end
			end
		}
	end

	def list_followers
		rpl = parsehtml oauth_get('/1/statuses/friends.xml').content, true
		fold_xml(rpl)
		rpl.find_all { |e| e.type == 'screen_name' }.reverse.map { |e| e['str'] }.join(' ')
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when /^!tw(?:ee|i)t(?:t|ter)?\s+(\S.*)/
			msg = auto2utf($1)
			#msg = HttpServer.htmlentitiesenc(msg)
			pg = oauth_post('/1/statuses/update.xml', 'status' => msg)
			irc.repl(pg.status == 200 ? "http://twitter.com/#{account}" : 'fail')
		when /^!follow\s+(\S.*)/
			pg = oauth_post('/friendships/create.xml', 'screen_name' => $1, 'follow' => 'true')
			irc.repl(pg.status == 200 ? 'ok' : 'fail ' + pg.content.inspect)
		when /^!nofollow\s+(\S.*)/
			pg = oauth_post('/friendships/destroy.xml', 'screen_name' => $1)
			irc.repl(pg.status == 200 ? 'ok' : 'fail')
		when /^!follow(ing|ed|s)$/
			irc.repl list_followers
		end
	end

	def help ; "Twitter to irc - !twit <publish_msg> | !follow <account> | !nofollow <account> | !following" end

	# http get to a oauth-enabled server
	# url should be the base url, with request parameters passed as a hash
	# e.g. to get /foo/bar?a=b&c=d, use oauth_get("/foo/bar", "a" => "b", "c" => "d")
	# (this is needed for the oauth signature)
	def oauth_get(url, parms={})
		pdata = parms.map { |k, v| v ? oauth_escape(k) + '=' + oauth_escape(v) : oauth_escape(k) }.join('&')
		hdrs = oauth_hdr('GET', url, parms)
		url += '?' + pdata if pdata != ''
		HttpClient.open("https://api.twitter.com/") { |hc| hc.get(url, nil, hdrs) }
	end

	# post to a oauth-enabled server
	# XXX we append the post data to the url (and still send as POST form) to work with the twitter website,
	# but this is contrary to the OAuth RFC (from my understanding)
	def oauth_post(url, parms={})
		pdata = parms.map { |k, v| oauth_escape(k) + '=' + oauth_escape(v) }.join('&')
		hdrs = oauth_hdr('POST', url, parms).merge('Content-type' => 'application/x-www-form-encoded')
		url += '?' + pdata if pdata != ''	# XXX twitter-specific workaround
		HttpClient.open("https://api.twitter.com/") { |hc| hc.post_raw(url, pdata, hdrs) }
	end

	# return the OAuth Authorization header
	def oauth_hdr(method, url, parms={})
		oauth = oauth_parms(method, url, parms)
		{ 'Authorization' => 'OAuth ' + oauth.map { |k, v| "#{k}=\"#{oauth_escape(v)}\"" }.join(",\n    ") }
	end

	# return the oauth params hash (to be used in the authorization header / get params)
	# from the method, pure url (no query parameters), and request parameters
	# additionnal 'oauth_' header entries can be specified in the @oauth[:oauth_supp] hash (deleted here after use)
	def oauth_parms(method, url, parms, base_url='https://api.twitter.com')
		base_str = method.upcase + '&' + oauth_escape(base_url.downcase + url) + '&'

		oauth = { 'oauth_consumer_key' => @oauth[:consumer_key], 'oauth_token' => @oauth[:token],
				'oauth_nonce' => rand(1<<32).to_s(16), 'oauth_signature_method' => 'HMAC-SHA1',
				'oauth_timestamp' => (Time.now.to_i + rand(180)-90) }

		oauth.update @oauth.delete(:oauth_supp) if @oauth[:oauth_supp]
		parms = oauth.merge parms
		bdata = parms.to_a
		#bdata += @oauth[:getp].to_a if @oauth[:getp]	# copy of the url parameters when POSTing

		# get all request param, sorted, encode them individually, then reencode the full string
		base_str += oauth_escape(bdata.sort.map { |k, v| oauth_escape(k) + '=' + oauth_escape(v) }.join('&'))

		oauth.merge 'oauth_signature' => oauth_hmacsha1(base_str)
	end

	# oauth-specific url encoding (needed for crypto signature correctness)
	def oauth_escape(str)
		str.to_s.gsub(/[^a-zA-Z0-9_~.-]/) { |o| '%%%02X' % o.unpack('C') }
	end

	def oauth_hmacsha1(text)
		key = oauth_escape(@oauth[:consumer_secret]) + '&' + oauth_escape(@oauth[:token_secret])
		mac = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha1'), key, text)
		[mac].pack('m*').split.join	# base64 encode
	end

	# to create your oauth parameters: log on twitter, click the 'api' link, create your application
	# initialize the @oauth hash with the provided consummer token/secret
	# run this function, it will query the website for a temporary token, and direct you to an url
	# visit the url, accept, and paste the pin code to the prompt, this will create the oauth_creds file
	# with the user credentials.
	#
	# use this in a console script, not in the irc bot !
	def oauth_register_new_user
		@oauth[:token] = @oauth[:token_secret] = ''

		@oauth[:oauth_supp] = { 'oauth_callback' => 'oob' }
		ans = oauth_post('/oauth/request_token')
		if ans.status != 200
			puts ans, "failed to request temporary token :("
			return
		end

		foo = ans.content.split('&').inject({}) { |h, s| h.update Hash[*s.split('=', 2)] }
		@oauth[:token] = foo['oauth_token']
		puts "Please visit https://api.twitter.com/oauth/authorize?oauth_token=#{@oauth['oauth_token']}"

		puts "Pin code?"
		pin = gets.chomp

		@oauth[:oauth_supp] = { 'oauth_verifier' => pin }
		ans = oauth_post('/oauth/access_token')
		if ans.status != 200
			puts ans, "failed to request user token - bad pin ?"
			return
		end
		foo = ans.content.split('&').inject({}) { |h, s| h.update Hash[*s.split('=', 2)] }
		p foo
		@oauth[:token] = foo['oauth_token']
		@oauth[:token_secret] = foo['oauth_token_secret']

		File.open('oauth_creds', 'a') { |fd| fd.puts @oauth[:consumer_token], @oauth[:consumer_secret], @oauth[:token], @oauth[:token_secret] }
		puts 'oauth_creds created'
		#puts oauth_get('/1/account/verify_credentials.xml')
	end


	# take a string, convert it to utf8 if it is not already
	# works pretty well for iso-8859-1, untested with others
	def auto2utf(s)
		b = s.unpack('C*')
		if b.find { |c| c >= 0x80 }  and not b.find { |c| c & 0xc0 == 0x80 }
			b.map { |c| c >= 0x80 ? [0xc0 | ((c & 0xc0) >> 6), 0x80 | (c & 0x3f)] : c }.flatten.pack('C*')
		else
			s
		end
	end
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

		q = (File.open('quotes.txt', 'rb') { |fd| fd.readlines }.map { |l| Quote.parse l } rescue [])
		arg.strip!
		parseint = proc {
			if not arg.empty? and (nr = Integer(arg) rescue nil) and nr < q.length and nr >= 0
				nr
			end
		}

		case type
		when 'add'
			quote = Quote.new(Time.now, owner, arg.gsub(/< ?(\S+?)>/, "\00303<\\1>\003"))
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
		if msg =~ /\/\S*\//
			list = (File.open('urls.txt', 'rb') { |fd| fd.readlines }.uniq.map { |u| u.split.first } rescue [])
			msg.scan(%r{\S+\.\S+/\S*/\S*|\S+://\S*}) { |u|
				pt = nil
				pt = 'old' if list.include? u
				dump_url(irc, u, pt)
			}
		end

		case msg
		when /^!urls?( .*|$)/
			arg = $1.strip
			list = (File.open('urls.txt', 'rb') { |fd| fd.readlines }.uniq rescue [])
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

	def dump_url(irc, u, pt=nil, rec_cnt=0)
		t = nil
		if u =~ %r{(.*twitter.com)(?:/#!)?(/.*/status(?:es)?/.*)}
			itsatweet = true
			u = $1 + $2
		end
		begin
			rescan = false
			u = u+'/' if u =~ %r{://[^/]*$}
			Timeout.timeout(40) {
				HttpClient.open(u) { |h|
					h.othersite_redirect = lambda { |u_, rec|
						next if rec
						pt ? pt << ' - ' : pt = ''
						pt << u_
						dump_url(irc, u_, pt, rec_cnt+1) if rec_cnt < 4
						nil
					}
					next if not ps = h.get(u).parse
					if ps.find { |e| e.type == 'meta' and e['http-equiv'] == 'refresh' and e['content'] =~ /0;URL=(.*)/i }
						# handle t.co style html redirects
						pt ? pt << ' - ' : pt = ''
						pt << $1
						dump_url(irc, $1, pt, rec_cnt+1) if rec_cnt < 4
						pt = nil
					end
					t = []
					tt = []
					intweet = false
					intitle = false
					ps.each { |e|
						case e.type
						when 'title'; intitle = true
						when '/title'; intitle = false; break unless itsatweet
						when 'p'; intweet = true if itsatweet and e['class'].to_s.split(' ').include?('tweet-text')
						when '/p'; break if intweet
						when 'String'; (intweet ? tt : t) << HttpServer.htmlentitiesdec(e['content']) if intitle or intweet
						end
					}
					t = tt if tt != []
					if t != []
						@last_url_rescan ||= Time.now - 61
						if @last_url_rescan < Time.now - 60 and t =~ /http/
							rescan = true
							@last_url_rescan = Time.now
						end
						irc.repl "#{pt + ' - ' if pt}" + t.join(' ')[0, 512], rescan
						pt = nil
					end
				}
			}
			irc.repl pt if pt
		rescue Object
			#irc.pm "#{$!.class} #{$!.message} #{$!.backtrace.first}", CONF[:admin_nick]
		end
		File.open('urls.txt', 'a') { |fd| fd.puts "#{u}   #{t[0, 512] if t}" }
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
			File.open('seen.txt', 'rb') { |fd| fd.readlines }.each { |sl|
				if sl =~ /^(\d+) (\S+) (.*)/
					seen[$2.downcase] = [$1.to_i, $3]
				end
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
			File.open('seen.txt', 'rb') { |fd| fd.readlines }.each { |l|
				next unless l =~ /^(\d+) (\S+) (.*)/
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
				if n == irc.nick
					return if m != ?@
					next
				end
				chmod(todo, m, n)
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

	def chmod(todo, m, n)
		#$blacklist ||= 'testic'
		case n
		#when /^#$blacklist/i; todo << ['-v', n] if m == ?+ ; todo << ['-o', n] if m == ?@
		when /bot/i; todo << ['-o', n] if m == ?@ ; todo << ['+v', n] if m != ?+
		else todo << ['+o', n] if m != ?@
		end
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when '!op'
			tg = to
			tg = irc.chan if tg[0] != ?# and tg[0] != ?&
			irc.send "mode #{tg} +o #{from.sub(/!.*/, '')}"
		when '!keepop'
			@keepop = true
			irc.repl 'ok'
		when '!nokeepop'
			@keepop = false
			irc.send "mode #{irc.chan} -o #{irc.nick}"
			irc.repl 'ok'
		end
	end

	def help ; "op all chan when bot is oped - also !op / !(no)keepop" end
end

class Youtube
	def initialize(irc)
		irc.plugin_msg << self
	end

	def handle_msg(irc, msg, from, to)
		case msg
		when /www.youtube.com\/watch\?v=([\w-]*)/
			return if not defined? HttpClient
			id = $1
			pg = HttpClient.open("http://www.youtube.com/") { |h| h.get("/get_video_info?video_id=#{id}") }
			tok = pg.content.to_s.split('&').map { |s| s.split('=', 2) }.assoc('token').to_a[1]
			url = nil
			if tok and fmt = [37, 22, 35, 18, 5, 17, 13].find { |f| HttpClient.open("http://www.youtube.com/") { |h|
				url = "http://www.youtube.com/get_video?video_id=#{id}&t=#{tok}&fmt=#{fmt}"
				h.head(url).status != 404
			} }
				irc.repl url
			end
		end
	end

	def help ; "shows youtube video url" end
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
			pl = irc.plugin_msg.sort_by { |pl_| pl_.class.name.to_s.length }.find { |pl_| pl_.class.name.downcase.include?(name) }
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

	# wait until data can be read on sock
	# returns true on data, false on timeout
	def wait_read(s, timeout=nil)
		return true if s.respond_to?(:pending) and s.pending > 0
		r = IO.select([s], nil, nil, timeout).to_a[0]
		r.to_a.include?(s)
	end

	def connect
		@sock = TCPSocket.open @host, @port
		if CONF[:ircd_ssl]
			@sock = OpenSSL::SSL::SSLSocket.new(@sock, OpenSSL::SSL::SSLContext.new)
			@sock.sync_close = true
			@sock.connect
			# YAY OPEN FUCKING SSL
			def @sock.pending
				@rbuffer.to_s.length + super()
			end
		end
		send "pass #{CONF[:ircd_pass]}" if CONF[:ircd_pass]
		send "user #@uhost", "nick #@nick"
		loop do
			wait_read(@sock)
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

		CONF[:more_chans].each { |c| send "join #{c}" } if CONF[:more_chans]
	end

	def run
		connect
		loop { run_loop }
	end

	def run_loop
		if not wait_read(@sock, 0.5)
			handle_timeout
		else
			handle_sock @sock.gets.chomp
		end
	end

	def send(*l)
		l.each { |ll|
			puts "#{Time.now.strftime '%H:%M'} > #{ll}" if $VERBOSE
			@sock.write ll.chomp << "\r\n"
		}
	end

	def pm(ll, dst=@chan, rescan=false)
		ll.to_s.gsub("\r", '').each_line { |l|	# g hax fix
			l.chomp!
			send "PRIVMSG #{dst} :#{l.empty? ? ' ' : l}"
			handle_privmsg @nick, dst, l if rescan
		}
	end

	attr_accessor :repltarget
	def repl(l, rescan=false) pm(l, @repltarget, rescan) end

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
		# rb19 cant motherfucking fork after $stdout.close...
		exit! if fork
		while chld = fork
			$stdin.close rescue nil
			$stdout.close rescue nil
			$stderr.close rescue nil
			sleep(1200)
			loop {
				begin
					Process.waitpid(chld)
				rescue Errno::ECHILD
					break
				end
			}
		end
		$stdin.close rescue nil
		$stdout.close rescue nil
		$stderr.close rescue nil
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
	#:ircd_pass => 'lolz',
	:chan => '#koolz',
	#:chan_pass => 's3cr3t',
	#:more_chans => ['#foo', '#bar bar_pass'],
	:nick => '`bot',
	:admin_nick => 'bob',
	:admin_re => /^bob!~marcel@roots.org$/,
	:twitter_account => 'bla',
	:twitter_oauth_file => 'secret_oauth.txt',
	:plugins => [Admin, GoogleSearch, GoogleTranslate, RSS, Twitter, Quote, Url, Seen, Op, Help]
}

IrcBot.start

end
