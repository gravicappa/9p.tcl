proc TODO: args {
  puts stderr "TODO: $args"
}

array set 9msg_fmt {
  hdr {u4 size u1 type u2 tag}
  stat {u2 size u2 type u4 dev qid qid u4 mode u4 atime u4 mtime u8 length
        s name s uid s gid s muid}
  Tversion {u4 msize s version}
  Rversion {u4 msize s version}
  Tauth {u4 afid s uname s aname}
  Rauth {qid aqid}
  Terror {}
  Rerror {s ename}
  Tflush {u2 oldtag}
  Rflush {}
  Tattach {u4 fid u4 afid s uname s aname}
  Rattach {qid qid}
  Twalk {u4 fid u4 newfid s* wname}
  Rwalk {qid* wqid}
  Topen {u4 fid u1 mode}
  Ropen {qid qid u4 iounit}
  Tcreate {u4 fid s name u4 perm u1 mode}
  Rcreate {qid qid u4 iounit}
  Tread {u4 fid u8 offset u4 count}
  Rread {d4 data}
  Twrite {u4 fid u8 offset d4 data}
  Rwrite {u4 count}
  Tclunk {u4 fid}
  Rclunk {}
  Tremove {u4 fid}
  Rremove {}
  Tstat {u4 fid}
  Rstat {d2 stat}
  Twstat {u4 fid d2 stat}
  Rwstat {}
}

set 9msg_order {version auth attach error flush walk open create read write
                clunk remove stat wstat}
array set 9mapping {}
array set 9ctx {}

proc 9init_msgs {} {
  global 9msg_fmt 9msg_order 9mapping
  set i 100
  foreach m $9msg_order {
    set 9msg_fmt($i) $9msg_fmt(T$m)
    set 9mapping(T$m) $i
    set 9mapping($i) T$m
    incr i
    set 9msg_fmt($i) $9msg_fmt(R$m)
    set 9mapping(R$m) $i
    set 9mapping($i) R$m
    incr i
  }
}

proc 9msg_number {key} {
  global 9mapping
  return [expr {([string is integer $key]) ? $key : $9mapping($key)}]
}

9init_msgs

array set 9p {
  PORT 564
  VERSION "9P2000"

  NOTAG 0xffff
  NOFID 0xffffffff
  DMDIR 0x80000000
  DMAPPEND 0x40000000
  DMEXCL 0x20000000
  DMTMP 0x04000000
  QDIR 0x80
  OREAD 0
  OWRITE 1
  ORDWR 2
  OEXEC 3
  OTRUNC 0x10
  ORCLOSE 0x40
}

set 9session_vars {msize 4096
                   buf ""
                   .tag {}
                   .fid {}}

array set 9open_modes [list r $9p(OREAD) \
                            r+ $9p(ORDWR) \
                            w [expr {$9p(OWRITE) | $9p(OTRUNC)}] \
                            w+ [expr {$9p(ORDWR) | $9p(OTRUNC)}] \
                            a $9p(OWRITE) \
                            a+ $9p(ORDWR)]

array set 9chan_open_modes {r {read}
                            r+ {read write}
                            w {write}
                            w+ {read write}
                            a {write}
                            a+ {read write}}

array set 9log_tags {connection 1 dbg 1 data 0}

proc puts_log {tag msg} {
  global 9log_tags
  if {[info exists 9log_tags($tag)] && $9log_tags($tag)} {
    puts stderr "# $tag: $msg"
    flush stderr
  }
}

if {[info command encoding] eq ""} {
  proc 9bin_from_utf8 {str} {return $str}

  proc 9bin_len {str} {
    binary scan $str H* x
    return [expr {[string length $x] >> 1}]
  }

  proc 9bin_range {str start {end "end"}} {
    set len [9bin_len $str]
    if {$end eq "end" || $end >= $len} {
      set end [expr {$len - 1}]
    }
    binary scan $str "x${start}a[expr {$end - $start + 1}]" ret
    return $ret
  }
} else {
  interp alias {} 9bin_from_utf8 {} encoding convertto utf-8
  interp alias {} 9bin_len {} string length
  interp alias {} 9bin_range {} string range
}

proc 9bin_read {stream fmt len var} {
  upvar 1 $var x
  upvar 1 $stream s
  set end [expr {$s(off) + $len}]
  switch -- $fmt {
    * {set x [9bin_range $s(buf) $s(off) [expr {$end - 1}]]}
    default {binary scan [9bin_range $s(buf) $s(off) [expr {$end - 1}]] $fmt x}
  }
  set s(off) $end
}

proc 9read_field {stream type var} {
  upvar 1 $var ret
  upvar 1 $stream s
  switch -- $type {
    u1 {9bin_read s cu1 1 ret}
    u2 {9bin_read s su1 2 ret}
    u4 {9bin_read s iu1 4 ret}
    u8 {9bin_read s wu1 8 ret}
    qid {
      9bin_read s cu1 1 mode
      9bin_read s iu1 4 version
      9bin_read s wu1 8 path
      set ret [list $mode $version $path]
    }
    d2 - s {
      9bin_read s su1 2 len
      set ret {}
      9bin_read s * $len ret
      if {$type eq "s"} {
        catch {set ret [encoding convertfrom utf-8 $ret]}
      }
    }
    d4 {
      9bin_read s iu1 4 len
      set ret {}
      9bin_read s * $len ret
    }
    qid* {
      9bin_read s su1 2 n
      set ret {}
      for {set i 0} {$i < $n} {incr i} {
        9read_field s qid x
        lappend ret $x
      }
    }
    s* {
      9bin_read s su1 2 n
      set ret {}
      for {set i 0} {$i < $n} {incr i} {
        9read_field s s x
        lappend ret $x
      }
    }
    default {error "Type $type is unsupported"}
  }
}

proc 9dec_msg {type data var} {
  global 9msg_fmt
  upvar 1 $var msg
  set stream(off) 0
  set stream(buf) $data
  foreach {t key} $9msg_fmt($type) {
    9read_field stream $t msg($key)
  }
}

proc 9enc_field {type value} {
  set buf {}
  switch -- $type {
    u1 {append buf [binary format cu1 $value]}
    u2 {append buf [binary format su1 $value]}
    u4 {append buf [binary format iu1 $value]}
    u8 {append buf [binary format wu1 $value]}
    qid {
      append buf [9enc_field u1 [lindex $value 0]]
      append buf [9enc_field u4 [lindex $value 1]]
      append buf [9enc_field u8 [lindex $value 2]]
    }
    s {
      set str [9bin_from_utf8 $value]
      append buf [binary format su1 [9bin_len $str]]
      append buf $str
    }
    qid* {
      append buf [9enc_field u2 [llength $value]]
      foreach x $value {
        append buf [9enc_field qid $x]
      }
    }
    s* {
      append buf [9enc_field u2 [llength $value]]
      foreach x $value {
        append buf [9enc_field s $x]
      }
    }
    d2 {
      append buf [binary format su1 [9bin_len $value]]
      append buf $value
    }
    d4 {
      append buf [binary format iu1 [9bin_len $value]]
      append buf $value
    }
    default {error "Type $type is unsupported"}
  }
  return $buf
}

proc 9enc_msg {var} {
  global 9msg_fmt
  upvar 1 $var msg
  set buf {}
  foreach {t key} $9msg_fmt($msg(type)) {
    append buf [9enc_field $t $msg($key)]
  }
  set size [expr {[9bin_len $buf] + 7}]
  return [binary format iu1cu1su1 $size $msg(type) $msg(tag)]$buf
}

proc 9init_ids {name chan} {
  global 9ctx
  set 9ctx($chan/.$name) {}
}

proc 9clear_ids {name chan} {
  global 9ctx
  unset -nocomplain 9ctx($chan/.$name)
}

proc 9new_id {name chan} {
  global 9ctx
  set i 0
  set tag {}
  foreach a $9ctx($chan/.$name) {
    if {$a != 0xffffffff} {
      for {set j 0} {$j < 32 && [expr {$a & (1 << $j)}]} {incr j} {}
      lset 9ctx($chan/.$name) $i [expr {$a | (1 << $j)}]
      set tag [expr {($i << 5) + $j}]
      break
    }
    incr i
  }
  if {$tag == {}} {
    set tag [expr {($i << 5)}]
    lappend 9ctx($chan/.$name) 1
  }
  return $tag
}

proc 9rm_id {name tag chan} {
  global 9ctx
  set i [expr {$tag >> 32}]
  set j [expr {$tag & 0xffffffff}]
  set a [lindex $9ctx($chan/.$name) $i]
  lset 9ctx($chan/.$name) $i [expr {$a & ~(1 << $j)}]
}

proc 9process_packet {chan} {
  global 9ctx
  set buf $9ctx($chan/buf)
  binary scan $buf iu1 msize
  if {$msize > [9bin_len $buf] || $msize < 7} {
    # error
    return
  }
  set msg [9bin_range $buf 0 $msize]
  set 9ctx($chan/buf) [9bin_range $buf $msize end]
  binary scan $msg iu1csu1 _ _ tag
  9rm_id tag $tag $chan
  if {[info exists 9ctx($chan/handler/$tag)]} {
    uplevel #0 $9ctx($chan/handler/$tag) [list $msg]
  } else {
    TODO: do something then tag handler is not set
    #set 9ctx($chan/pool/$tag) $msg
  }
}

proc 9recv_msg {chan} {
  global 9ctx
  while 1 {
    if {[eof $chan] || [catch {set buf [read $chan $9ctx($chan/msize)]}]} {
      puts_log connection "Connection unexpectedly closed."
      return -1
    }
    if {$buf eq ""} {
      return 0
    }
    puts_log data "<<<<([9bin_len $buf]): [hexdump $buf]"
    set buf [append 9ctx($chan/buf) $buf]
    binary scan $buf iu1 msgsize
    if {$msgsize <= [9bin_len $buf]} {
      set 9ctx($chan/buf) $buf
      return 1
    }
  }
}

proc 9recv_data {chan} {
  switch -- [9recv_msg $chan] {
    -1 {
      global 9ctx
      foreach {k v} [array get 9ctx $chan/var/*] {
        set 9ctx($k) [list type [9msg_number Rerror] \
                           ename "Connection closed."]
      }
      fileevent $chan readable {}
      return false
    }
    0 {return true}
    1 {9process_packet $chan}
  }
}

proc 9process_msg {msgvar chan exptype buf} {
  global 9ctx 9msg_fmt
  upvar 1 $msgvar msg
  binary scan $buf iu1csu1 size type tag
  unset -nocomplain 9ctx($chan/handler/$tag)
  if {![info exists 9msg_fmt($type)]} {
    return -code error "Unknown message type $type"
  }
  if {$exptype + 1 != $type && $type != [9msg_number Rerror]} {
    return -code error "Unexpected message type $type for $exptype"
  }
  9dec_msg $type [9bin_range $buf 7 end] msg
  set msg(chan) $chan
  set msg(type) $type
  set msg(tag) $tag
}

proc 9recv_async {msgvar chan exptype code buf} {
  9process_msg msg $chan $exptype $buf
  eval $code
}

proc 9sync_handler {msgvar data code} {
  set c [list array set $msgvar $data]\n$code
  uplevel 2 $c
}

proc 9send_msg {msgvar chan sync code} {
  global 9ctx 9msg_fmt
  upvar 1 $msgvar m
  set m(tag) [9new_id tag $chan]
  set m(type) [9msg_number $m(type)]
  set buf [9enc_msg m]
  set code1 $code
  if {$sync} {
    set code1 [string map [list %M $msgvar] {
      global 9ctx
      set 9ctx($%M(chan)/var/$%M(tag)) [array get %M]
    }]
  }
  set key $chan/handler/$m(tag)
  set 9ctx($key) [list 9recv_async $msgvar $chan $m(type) $code1]
  puts_log data ">>>>([9bin_len $buf]): [hexdump $buf]"
  puts -nonewline $chan $buf
  flush $chan
  if {!$sync} {
    return $m(tag)
  }
  set 9ctx($chan/var/$m(tag)) {}
  vwait 9ctx($chan/var/$m(tag))
  set ret $9ctx($chan/var/$m(tag))
  unset -nocomplain 9ctx($chan/var/$m(tag))
  return [9sync_handler $msgvar $ret $code]
}

proc 9stop {chan} {
  global 9ctx
  array unset 9ctx $chan/*
  fileevent $chan readable {}
}

proc 9start {chan} {
  global 9p 9ctx 9session_vars
  fconfigure $chan -blocking 0 -translation binary
  catch {fconfigure $chan -translation binary -encoding binary}
  foreach {k v} $9session_vars {
    set 9ctx($chan/$k) $v
  }
  set msg(type) Tversion
  set msg(msize) 65536
  set msg(version) $9p(VERSION)
  fileevent $chan readable [list 9recv_data $chan]
  9send_msg msg $chan 1 {
    global 9ctx 9p
    if {[info exists msg(ename)]} {
      return -code error "9p error: $msg(ename)"
    }
    if {$msg(version) ne $9p(VERSION)} {
      9stop $chan
      return -code error "Version $msg(version) is not supported."
    }
    if {$9ctx($chan/msize) > $msg(msize)} {
      set 9ctx($chan/msize) $msg(msize)
    }
  }
  return true
}

proc 9named {a def} {
  upvar 1 _ _
  array set _ $def
  foreach {key value} $a {
    if {![info exists _($key)]} {
      error "bad option '$key', should be one of: [lsort [array names _]]"
    }
    set _($key) $value
  }
}

proc 9attach {chan args} {
  global 9p
  set user "noname"
  catch {set user $tcl_platform(user)}
  9named $args [list -uname $user -aname "" -afid $9p(NOFID) -cmd {}]
  set msg(type) Tattach
  set msg(fid) [9new_id fid $chan]
  set msg(afid) $_(-afid)
  set msg(uname) $_(-uname)
  set msg(aname) $_(-aname)
  set sync 0
  if {$_(-cmd) eq {}} {
    set sync 1
    set _(-cmd) "expr {$msg(fid)}"
  }
  return [9send_msg msg $chan $sync $_(-cmd)]
}

proc 9auth {chan args} {
  set user "noname"
  catch {set user $tcl_platform(user)}
  9named $args [list -uname $user -aname "" -afid $9p(NOFID) -sync 0 -cmd {}]
  set msg(type) Tauth
  set msg(afid) [9new_id fid $chan]
  set msg(uname) $_(-uname)
  set msg(aname) $_(-aname)
  set cmd [expr {($_(-cmd) eq {}) ? "expr {$msg(fid)}" : $_(-cmd)}]
  return [9send_msg msg $chan $_(-sync) $cmd]
}

proc 9flush_handler {chan tag cmd} {
  global 9ctx
  unset -nocomplain 9ctx($chan/var/$tag) 9ctx($chan/handler/$tag)
  9rm_id tags $tag $chan
  uplevel 1 $cmd
}

proc 9flush {chan tag {cmd ""}} {
  set msg(type) Tflush
  set msg(oldtag) $tag
  set sync [expr {$cmd eq {}}]
  return [9send_msg msg $chan $sync [9flush_handler $chan $tag $cmd]]
}

proc 9walk_handler {var n cmd} {
  upvar 1 $var msg
  if {[info exists msg(ename)]} {
    return -code error "9p error: $msg(ename)"
  }
  if {$n > [llength $msg(wqid)]} {
    return -code error "walk error"
  }
  uplevel 1 $cmd
}

proc 9walk_aux {chan fid newfid names sync cmd} {
  global 9ctx
  set size [expr {4 + 1 + 2 + 4 + 4 + 2}]
  set i 0
  foreach name $names {
    set ds [expr {2 + [9bin_len [9bin_from_utf8 $name]]}]
    if {$size + $ds > $9ctx($chan/msize)} {
      break
    }
    incr size $ds
    incr i
  }
  set msg(type) Twalk
  set msg(fid) $fid
  set msg(newfid) $newfid
  set msg(wname) [lrange $names 0 $i]
  set names [lrange $names $i+1 end]
  if {$cmd eq {}} {
    set cmd {expr {$msg(newfid)}}
  }
  if {$names eq {}} {
    set c $cmd
  } else {
    set c [list 9walk_aux $chan $fid $newfid $names $sync $cmd]
  }
  set n [llength $msg(wname)]
  return [9send_msg msg $chan $sync [list 9walk_handler msg $n $c]]
}

proc 9cleanpath {path} {return [string trim [regsub -all {//*} $path {/}] /]}

proc 9walk {chan fid path {cmd ""}} {
  set names [split [9cleanpath $path] /]
  set newfid [9new_id fid $chan]
  set sync [expr {$cmd eq {}}]
  return [9walk_aux $chan $fid $newfid $names $sync $cmd]
}

proc 9open {chan fid mode {cmd ""}} {
  global 9open_modes
  set msg(type) Topen
  set msg(fid) $fid
  if {[string is integer $mode]} {
    set msg(mode) $mode
  } else {
    set msg(mode) $9open_modes($mode)
  }
  set sync [expr {$cmd eq {}}]
  if {$cmd eq {}} {
    set cmd {
      if {[info exists msg(ename)]} {
        return -code error "9p error: $msg(ename)"
      }
      expr {$msg(iounit)}
    }
  }
  return [9send_msg msg $chan $sync $cmd]
}

proc 9create {chan fid name perm mode {cmd ""}} {
  global 9open_modes
  set msg(type) Tcreate
  set msg(fid) $fid
  set msg(name) $name
  if {[string is integer $mode]} {
    set msg(mode) $mode
  } else {
    set msg(mode) $9open_modes($mode)
  }
  set msg(perm) $perm
  set sync [expr {$cmd eq {}}]
  if {$cmd eq {}} {
    set cmd {
      if {[info exists msg(ename)]} {
        return -code error "9p error: $msg(ename)"
      }
      expr {$msg(iounit)}
    }
  }
  return [9send_msg msg $chan $sync $cmd]
}

proc 9read {chan fid offset count {cmd ""}} {
  set msg(type) Tread
  set msg(fid) $fid
  set msg(offset) $offset
  set msg(count) $count
  set sync [expr {$cmd eq {}}]
  if {$cmd eq {}} {
    set cmd {
      if {[info exists msg(ename)]} {
        return -code error "9p error: $msg(ename)"
      }
      expr {"$msg(data)"}
    }
  }
  return [9send_msg msg $chan $sync $cmd]
}

proc 9write {chan fid offset data {cmd ""}} {
  set msg(type) Twrite
  set msg(fid) $fid
  set msg(offset) $offset
  set msg(data) $data
  set sync [expr {$cmd eq {}}]
  if {$cmd eq {}} {
    set cmd {
      if {[info exists msg(ename)]} {
        puts_log dbg "9p error: $msg(ename)"
        return -code error "9p error: $msg(ename)"
      }
      unset msg(data)
      expr {"$msg(count)"}
    }
  }
  return [9send_msg msg $chan $sync $cmd]
}

proc 9clunk {chan fid {cmd ""}} {
  set msg(type) Tclunk
  set msg(fid) $fid
  set sync [expr {$cmd eq {}}]
  return [9send_msg msg $chan $sync $cmd]
}

proc 9remove {chan fid {cmd ""}} {
  set msg(type) Tremove
  set msg(fid) $fid
  set sync [expr {$cmd eq {}}]
  return [9send_msg msg $chan $sync $cmd]
}

proc 9stat {chan fid {cmd ""}} {
  set msg(type) Tstat
  set msg(fid) $fid
  set sync [expr {$cmd eq {}}]
  if {$cmd eq {}} {
    set cmd {
      if {[info exists msg(ename)]} {
        return -code error "9p error: $msg(ename)"
      }
      9dec_msg stat $msg(stat) stat
      array get stat
    }
  }
  return [9send_msg msg $chan $sync $cmd]
}

proc 9wstat {chan fid statvar {cmd ""}} {
}

proc 9session_open {chan args} {
  9start $chan
  set rootfid [9attach $chan {*}$args]
  return [list session $chan $rootfid]
}

proc 9file_ctx {x type chanvar fidvar} {
  upvar 1 $chanvar c
  upvar 1 $fidvar f
  foreach {id c f} $x break
  if {$id ne $type} {
    return -code error "Invalid $type."
  }
}

proc 9session_close {session} {
  global 9ctx
  9file_ctx $session session chan rootfid
  9clunk $chan $rootfid
  9stop $chan
}

proc 9file_open {session name mode} {
  global 9ctx
  9file_ctx $session session chan rootfid
  set name [9cleanpath $name]
  if {[catch {set fid [9walk $chan $rootfid $name]}]} {
    set fid [9walk $chan $rootfid [file dirname $name]]
    set perm 0o644
    set iounit {9create $chan $fid [file basename $name] $mode $perm}
  } else {
    set iounit [9open $chan $fid $mode]
  }
  set 9ctx($chan/file/$fid/iounit) $iounit
  set 9ctx($chan/file/$fid/off) 0
  set 9ctx($chan/file/$fid/inbuf) ""
  set 9ctx($chan/file/$fid/readable_cmd) {}
  return [list file $chan $fid]
}

proc 9file_close {file} {
  global 9ctx
  9file_ctx $file file chan fid
  array unset 9ctx $chan/file/$fid/*
  9clunk $chan $fid
}

proc 9file_read_async {file {size ""}} {
  global 9ctx
  9file_ctx $file file chan fid
  if {![info exists 9ctx($chan/file/$fid/inbuf)]} {
    return {}
  }
  set buf $9ctx($chan/file/$fid/inbuf)
  set len [9bin_len $buf]
  if {$size eq "" || $len < $size} {
    return $buf
  }
  set 9ctx($chan/file/$fid/inbuf) [9bin_range $buf $size end]
  return [9bin_range $buf 0 $size-1]
}

proc 9file_read {file {size ""}} {
  global 9ctx
  9file_ctx $file file chan fid
  if {[info exists 9ctx($chan/file/$fid/inside_readable)]} {
    return [9file_read_async $file $size]
  }
  set off $9ctx($chan/file/$fid/off)
  set dsize $size
  if {$size eq "" || $size + 23 > $9ctx($chan/file/$fid/iounit)} {
    set dsize [expr {$9ctx($chan/file/$fid/iounit) - 23}]
  }
  set data $9ctx($chan/file/$fid/inbuf)
  set read_bytes [9bin_len $data]
  while {$dsize > 0} {
    set d [9read $chan $fid $off $dsize]
    set n [9bin_len $d]
    incr read_bytes $n
    incr off $n
    set 9ctx($chan/file/$fid/off) $off
    append data $d
    if {$d eq ""} {
      break
    }
    if {$size ne "" && $read_bytes + $dsize > $size} {
      set dsize [expr {$size - $read_bytes}]
    }
  }
  return $data
}

proc 9file_read_handler {file off size var cmd} {
  global 9ctx
  upvar 1 $var msg
  if {[info exists msg(ename)]} {
    return -code error "9p error: $msg(ename)"
  }
  9file_ctx $file file chan fid
  incr 9ctx($chan/file/$fid/off) [9bin_len $msg(data)]
  append 9ctx($chan/file/$fid/inbuf) $msg(data)
  set 9ctx($chan/file/$fid/inside_readable) 1
  uplevel #0 $cmd
  unset -nocomplain 9ctx($chan/file/$fid/inside_readable)
  9file_readable $file $cmd
}

proc 9file_readable {file args} {
  global 9ctx
  9file_ctx $file file chan fid
  if {$args eq ""} {
    catch {return $9ctx($chan/file/$fid/readable_cmd)}
    return
  }
  set cmd [lindex $args 0]
  set 9ctx($chan/file/$fid/readable_cmd) $cmd
  if {[info exists 9ctx($chan/file/$fid/inside_readable)]} {
    return
  }
  if {$cmd ne ""} {
    set off $9ctx($chan/file/$fid/off)
    set size [expr $9ctx($chan/file/$fid/iounit)]
    set c [list 9file_read_handler $file $off $size msg $cmd]
    set tag [9read $chan $fid $off $size $c]
  } else {
    vwait 9ctx($chan/file/$fid/inbuf)
  }
  return
}

proc 9file_write {file data} {
  global 9ctx
  9file_ctx $file file chan fid
  set off $9ctx($chan/file/$fid/off)
  set size [9bin_len $data]
  set dsize $size
  if {$dsize > $9ctx($chan/file/$fid/iounit)} {
    set dsize [expr $9ctx($chan/file/$fid/iounit)]
  }
  set i 0
  while {$dsize > 0} {
    set end [expr {$i + $dsize - 1}]
    set n [9write $chan $fid $off [9bin_range $data $i $end]]
    incr i $n
    incr off $n
    set 9ctx($chan/file/$fid/off) $off
    if {$i + $dsize > $size} {
      set dsize [expr {$size - $i}]
    }
  }
  return $i
}

proc 9file_seek {file offset {origin "start"}} {
  global 9ctx
  9file_ctx $file file chan fid
  set off $9ctx($chan/file/$fid/off)
  switch -- $origin {
    start {set 9ctx($chan/file/$fid/off) $offset}
    current {incr 9ctx($chan/file/$fid/off) $offset}
    end {
      9file_stat $file stat
      set off [expr {$stat(length) - $offset}]
      set 9ctx($chan/file/$fid/off) [expr {$off >= 0 ? $off : 0}]
    }
  }
  return
}

proc 9file_tell {file} {
  global 9ctx
  9file_ctx $file file chan fid
  return $9ctx($chan/file/$fid/off)
}

proc 9file_stat {file var} {
  upvar 1 $var stat
  9file_ctx $file file chan fid
  array set stat [9stat $chan $fid]
}

proc 9file_ls {session path args} {
  set fd [9file_open $session $path r]
  set data [9file_read $fd]
  set i 0
  set size [9bin_len $data]
  set ret {}
  while {$i < $size} {
    binary scan [9bin_range $data $i [expr {$i + 3}]] su1 s
    9dec_msg stat [9bin_range $data $i [expr {$i + $s - 1}]] stat
    set d [9bin_range $data $i [expr {$i + $s - 1}]]
    incr i $s
    incr i 2
    lappend ret $stat(name)
  }
  9file_close $fd
  return $ret
}

proc 9file_mkdir {session path} {
  global 9p
  9file_ctx $session session chan rootfid
  set fid $rootfid
  set i 0
  set path [split [9cleanpath $path] /]
  foreach name $path {
    if {[catch {set fid [9walk $chan $fid $name]}]} {
      break
    }
    incr i
  }
  foreach name [lrange $path $i end] {
    set perm [expr {0o755 | $9p(DMDIR)}]
    set iounit [9create $chan $fid $name $perm 0]
  }
  9clunk $chan $fid
}

if {[info command chan] ne ""} {
  proc 9chan_initialize {chan fid self mode} {
    global 9ctx
    set key
    set 9ctx($chan/chan/$fid/$self/block) 1
    set 9ctx($chan/chan/$fid/$self/watch_write) 0
    set 9ctx($chan/chan/$fid/$self/watch_read) 0
    set 9ctx($chan/chan/$fid/$self/mode) $mode
    return {initialize finalize watch read write seek configure cget cgetall
            blocking}
  }

  proc 9chan_configure {chan fid self option value} {
    global 9ctx
    switch -- $option {
      -blocking {set 9ctx($chan/chan/$fid/$self/block) $value}
    }
  }

  proc 9chan_cget {chan fid self option} {
    global 9ctx
    switch -- $option {
      -blocking {return $9ctx($chan/chan/$fid/$self/block)}
    }
  }

  proc 9chan_cgetall {chan fid self} {
    return [list -blocking $9ctx($chan/chan/$fid/$self/block)]
  }

  proc 9chan_handle {file cmd self args} {
    9file_ctx $file file chan fid
    uplevel 1 [list 9chan_$cmd $chan $fid $self] $args
  }

  proc 9chan {file mode} {
    global 9chan_open_modes
    chan create $9chan_open_modes($mode) [list 9chan_handle $file]
  }
}

proc hexdump {s} {
  binary scan $s H* hex
  return $hex
}

proc test {} {
  global 9msg_fmt
  array set msg {
    tag 1
    type 100
    msize 1023
    version 9P2000
  }
  set buf [9enc_msg msg]
  puts "buf([9bin_len $buf]): [hexdump $buf]"
  puts "buf*: [hexdump [9bin_range $buf 4 end]]"
  9dec_msg [9msg_number Tversion] [9bin_range $buf 7 end] rmsg
  parray rmsg
}

proc test_fid {} {
  global 9ctx 9session_vars
  set chan x
  unset -nocomplain 9ctx
  foreach {k v} $9session_vars {
    set 9ctx($chan/$k) $v
  }
  for {set i 0} {$i < 10} {incr i} {
    set fid [9new_id fid $chan]
    puts "fid: $fid"
  }
}

proc test_simple {} {
  global 9ctx
  unset -nocomplain 9ctx
  if {[catch {info tclversion}]} {
    set fd [socket stream 127.0.0.1:5558]
  } else {
    set fd [socket 127.0.0.1 5558]
  }
  9start $fd
  set fid [9attach $fd]
  puts_log dbg "attach fid: $fid"
  set ret [9walk $fd $fid "fonts/list"]
  puts_log dbg "walk ret: $ret"
  if {![9open $fd $ret r]} {
    puts_log dbg "open failed"
  }
  set data [9read $fd $ret 0 65536]
  puts_log dbg "contents:\n---\n$data\n---"
  9clunk $fd $ret
  9stop $fd
  close $fd
}

proc test_fileio {} {
  global 9ctx
  unset -nocomplain 9ctx
  if {[catch {info tclversion}]} {
    set fd [socket stream 127.0.0.1:5558]
  } else {
    set fd [socket 127.0.0.1 5558]
  }
  set s [9session_open $fd]
  puts_log dbg "session: $s"
  set f [9file_open $s "fonts/list" r]
  puts_log dbg "f: $f"
  set data [9file_read $f]
  puts_log dbg "contents:\n---\n$data\n---"
  9file_close $f
  9session_close $s
  close $fd
}
