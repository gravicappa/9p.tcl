package require vfs

namespace eval 9p {
variable PORT 564
variable VERSION "9P2000"

variable NOTAG 0xffff
variable NOFID 0xffffffff
variable DMDIR 0x80000000
variable DMAPPEND 0x40000000
variable DMEXCL 0x20000000
variable DMTMP 0x04000000
variable QDIR 0x80
variable OREAD 0
variable OWRITE 1 
variable ORDWR 2
variable OEXEC 3
variable OTRUNC 0x10
variable ORCLOSE 0x40

variable session_vars
set session_vars {{set iounit 4096}
                  {set buf ""}
                  {{array set} pool {}}}

set Tmsg_fmt {
  Tversion "iS"
  Tauth "iSS"
  Terror ""
  Tflush "s"
  Tattach "iiSS"
  Twalk "iisR"
  Topen "ic"
  Tcreate "iSic"
  Tread "iwi"
  Twrite "iwD"
  Tclunk "i"
  Tremove "i"
  Tstat "i"
  Twstat "sR"
}

set Rmsg_fmt {
  Rversion "iS"
  Rauth "ciw"
  Rerror "S"
  Rflush ""
  Rattach "ciw"
  Rwalk "R"
  Ropen "csii"
  Rcreate "csii"
  Rread "D"
  Rwrite "i"
  Rclunk ""
  Rremove ""
  Rstat "sssiciwiiiwSSSS"
  stat "ssiciwiiiwSSSS"
  Rwstat ""
}

set commands {version auth attach error flush walk 
              open create read write clunk remove stat wstat}

variable open_modes
array set open_modes [list r $OREAD \
                           r+ $ORDWR \
                           w $OWRITE \
                           w+ $ORDWR \
                           a $OWRITE \
                           a+ $ORDWR]

variable chan_open_modes
array set chan_open_modes {r {read}
                           r+ {read write}
                           w {write}
                           w+ {read write}
                           a {write}
                           a+ {read write}}

variable cmd_name

proc DBG {msg} {
  puts stderr ";; $msg"
  flush stderr
}

proc named {args defaults} {
  upvar 1 "" ""
  array set "" $defaults
  foreach {key value} $args {
    if {![info exists ($key)]} {
      error "bad option '$key', should be one of: [lsort [array names {}]]"
    }
    set ($key) $value
  }
}

proc prep_cmd_numbers {commands} {
  set i 100
  foreach c $commands {
    foreach prefix {T R} {
      set cmd_name($i) $prefix$c
      variable $prefix$c
      set $prefix$c $i
      incr i
    }
  }
}

prep_cmd_numbers $commands

proc prep_cmd_encode {msg fmt} {
  variable $msg
  set len [string length $fmt]
  set args [list]
  set code [list]
  set fmt_fmt "cs"
  set fmt_args [list [set $msg] \$tag]

  for {set i 0} {$i < $len} {incr i} {
    set name item$i
    set t [string index $fmt $i]
    switch $t {
      S { 
        append code "set $name \[encoding convertto utf-8 \$$name\];\n"
        append code "set bytes$i \[string length \$$name\];\n"
        append fmt_fmt "sa\$\{bytes${i}\}"
        lappend fmt_args \$bytes$i
      }
      D {
        append code "set bytes$i \[string length \$$name\];\n"
        append fmt_fmt "ia\$\{bytes${i}\}"
        lappend fmt_args \$bytes$i
      }
      R { append fmt_fmt "a*" }
      default { append fmt_fmt $t }
    }
    lappend fmt_args \$$name
    lappend args $name
  }
  append code "binary format $fmt_fmt [join $fmt_args]"
  proc enc$msg [join [list tag $args]] $code
}

proc dbg_hex_dump {data {prefix "hex: "}} {
  binary scan $data H* hex
  set l [string length $hex]
  DBG "$prefix $hex"
}

proc dec_packet {fmt data vars} {
  #DBG "dec_packet {$fmt} {$data} {$vars}"
  set s 0
  foreach t $fmt v $vars {
    upvar $v var
    set f $t
    switch $t {
      cu1 { set end $s }
      su1 { set end [expr {$s + 1}] }
      iu1 { set end [expr {$s + 3}] }
      wu1 { set end [expr {$s + 7}] }
      D {
        binary scan [string range $data $s [expr {$s + 3}]] iu1 len
        incr s 4
        set end [expr {$s + $len - 1}]
        set f a$len
      }
      S - d {
        binary scan [string range $data $s [expr {$s + 1}]] su1 len
        incr s 2
        set end [expr {$s + $len - 1}]
        set f a$len
      }
      R { 
        set end [string length $data]
        set f a*
      }
      default { return -code error "Type $t is unsupported" }
    }
    binary scan [string range $data $s $end] $f var
    if {$t == "S"} {
      set var [encoding convertfrom utf-8 $var]
    }
    set s [expr {$end + 1}]
  }
}

proc prep_cmd_decode {msg fmt} {
  set i 0
  set f [list]
  set len [string length $fmt]
  foreach t [split $fmt {}] {
    if {$t ne ""} {
      switch $t {
        c - s - i - w { append t u1 }
      }
      lappend f $t
    }
  }
  interp alias {} [namespace current]::dec$msg \
               {} [namespace current]::dec_packet $f
}

proc prep_all_cmd_serialize {Tmsg_fmt Rmsg_fmt} {
  foreach {msg fmt} $Tmsg_fmt {
    prep_cmd_encode $msg $fmt
  }
  foreach {msg fmt} $Rmsg_fmt {
    prep_cmd_decode $msg $fmt
  }
}

prep_all_cmd_serialize $Tmsg_fmt $Rmsg_fmt

proc init_ids {name chan} {
  set ids [namespace current]::$name/$chan
  global $ids
  set $ids [list]
}

proc clear_ids {name chan} {
  set ids [namespace current]::$name/$chan
  global $ids
  unset $ids 
}

proc new_id {name chan} {
  set ids [namespace current]::$name/$chan
  global $ids
  set i 0
  set tag {}
  foreach a [set $ids] {
    if {$a != 0xffffffff} {
      for {set j 0} {$j < 32 && [expr {$a & (1 << $j)}]} {incr j} {}
      lset $ids $i [expr {$a | (1 << $j)}]
      set tag [expr {($i * 32) + $j}]
    }
    incr i
  }
  if {$tag == {}} {
    set tag [expr {($i * 32)}]
    lappend $ids 1
  }
  return $tag
}

proc rm_id {name tag chan} {
  set ids [namespace current]::$name/$chan
  global $ids
  set i [expr {$tag >> 32}]
  set j [expr {$tag & 0xffffffff}]
  set a [lindex [set $ids] $i]
  lset $ids $i [expr {$a & ~(1 << $j)}]
}

proc read_packet {nmsg chan} {
  set buf [namespace current]::buf/$chan
  set pool [namespace current]::pool/$chan
  global $buf $pool
  set msg [string range [set $buf] 0 $nmsg] 
  set $buf [string range [set $buf] $nmsg end]
  binary scan $msg iu1csu1 msize type tag
  array set $pool [list $tag $msg]
}

proc recv_data {chan} {
  set buf [namespace current]::buf/$chan
  set iounit [namespace current]::iounit/$chan
  global $iounit $buf
  if {![eof $chan]} {
    set data [read $chan [set $iounit]]
    if {[string length $data] > 0} {
      append $buf $data
      while {[string length [set $buf]] >= 7} {
        set nbuf [string length [set $buf]]
        binary scan [set $buf] iu1 nmsg
        if {$nmsg <= $nbuf} {
          read_packet $nmsg $chan
        } else {
          break
        }
      }
    }
  } else {
    DBG "Connection closed."
    cleanup $fd
  }
}

proc get_msg {tag chan} {
  set pool [namespace current]::pool/$chan
  global $pool
  vwait [set pool]($tag)
  set msg [set [set pool]($tag)]
  unset [set pool]($tag)
  return $msg
}

proc send_msg {chan type to} {
  set tag [new_id tag $chan]
  set data [eval [list encT$type $tag] $to]
  set size [string length $data]
  set buf [binary format i [expr {$size + 4}]]
  append buf $data
  puts -nonewline $chan $buf
  flush $chan
  return $tag
}

proc dec_msg {chan type tag from} {
  set ret [get_msg $tag $chan]
  rm_id tag $tag $chan
  binary scan $ret iu1csu1 rsize rtype rtag
  if {$rtype == [set [namespace current]::R$type]} {
    uplevel 1 [list decR$type [string range $ret 7 end] $from]
  } elseif {$rtype == [set [namespace current]::Rerror]} {
    decRerror [string range $ret 7 end] msg
    return -code error "Error: $msg"
  } else {
    return -code error "Wrong server responce (type: $rtype)"
  }
  return $rsize
}

proc send/recv {chan type to {from {}}} {
  set tag [send_msg $chan $type $to]
  uplevel 1 [list dec_msg $chan $type $tag $from]
}

proc init_session {chan} {
  global [namespace current]::session_vars
  init_ids tag $chan
  init_ids fid $chan
  foreach i $session_vars {
    lassign $i setter name value
    set var [namespace current]::$name/$chan
    global $var
    eval $setter $var [list $value]
  }
}

proc cleanup_session {chan} {
  global [namespace current]::session_vars
  clear_ids tag $chan
  clear_ids fid $chan
  foreach i $session_vars {
    lassign $i setter name value
    set v [namespace current]::$name/$chan
    global $v
    unset $v
  }
}

proc start {chan} {
  if {[fconfigure $chan -encoding] != "binary"} { 
    return -code error "Channel $chan encoding is not binary."
  }
  init_session $chan
  fileevent $chan readable [list [namespace current]::recv_data $chan]

  set iounit [namespace current]::iounit/$chan
  global [namespace current]::VERSION $iounit

  send/recv $chan version [list [set $iounit] $VERSION] {riounit rver}
  if {$rver == $VERSION} {
    set $iounit [expr {min([set $iounit], $riounit)}]
  } else {
    return -code error "Unsupported version: $rver."
  }
}

proc stop {chan} {
  cleanup_session $chan
  fileevent $chan readable {}
}

##
## CHAN
## 

proc handle_initialize {chan fid self mode} {
  upvar $self fd
  set iounit [namespace current]::iounit/$chan
  global $iounit

  set hdr [expr {4 + 1 + 2 + 4}]
  array set fd {off 0
                inbuf ""
                outbuf ""
                block 1
                watch_write 0
                watch_read 0}
  set fd(mode) $mode
  set fd(iounit) [expr {[set $iounit] - $hdr}]
  return {initialize finalize watch read write seek configure cget cgetall 
          blocking}
}

proc handle_configure {chan fid self option value} {
  switch $option {
    -blocking { handle_blocking $chan $fid $self $value }
  }
}

proc handle_cget {chan fid self option} {
  upvar $self fd
  switch $option {
    -blocking { set ret $fd(block) }
  }
  return $ret
}

proc handle_cgetall {chan fid self} {
  upvar $self fd
  return [list -blocking $fd(block)]
}

proc read_file {chan fid self count} {
  upvar $self fd
  set count [expr {min($count, $fd(iounit))}]
  send/recv $chan read [list $fid $fd(off) $count] {data}
  append fd(inbuf) $data
  set nread [string length $data]
  incr fd(off) $nread
  if {$fd(watch_read)} { 
    after 1 [list chan postevent $self read]
  }
  return $nread
}

proc sched_read_file {chan fid self} {
  upvar $self fd
  set count $fd(iounit)
  after 1 [list [namespace current]::read_file $chan $fid $self $count]
}

proc handle_read {chan fid self count} {
  upvar $self fd
  set off $fd(off)
  if {$fd(block)} {
    set nread [read_file $chan $fid $self $count]
    set buf $fd(inbuf)
    set data [string range $buf 0 $nread]
    set fd(inbuf) [string range $buf $nread end]
  } else {
    set buf $fd(inbuf)
    set n [expr {min($count, [string length $buf])}]
    set data [string range $buf 0 $n]
    set fd(inbuf) [string range $buf $n end]
    sched_read_file $chan $fid $self
  }
  return $data
}

proc write_file {chan fid self off data} {
  upvar $self fd
  append fd(outbuf) $data
  set off $fd(off)
  set written 0
  while {1} {
    set len [string length $fd(outbuf)]
    if {$len <= 0} {
      break
    }
    set n [expr {min($fd(iounit), $len)}]
    set buf $fd(outbuf)
    send/recv $chan write [list $fid $off [string range $buf 0 $n]] {count}
    set fd(outbuf) [string range $buf $count end]
    incr fd(off) $count
    incr written $count
  }
  if {$fd(watch_write)} { 
    after 1 [list chan postevent $self write]
  }
  return [expr {min($written, [string length $data])}]
}

proc handle_write {chan fid self data} {
  upvar $self fd
  set off fd(off)
  if {$fd(block)} {
    set count [write_file $chan $fid $self $off $data]
  } else {
    after 1 [list write_file $chan $fid $self $off $fd(outbuf)]
    set count 0
  }
  return $count
}

proc handle_watch {chan fid self event} {
  upvar $self fd
  set fd(watch_read) 0
  set fd(watch_write) 0
  if {[lsearch $event read] >= 0} {
    set fd(watch_read) 1
    if {!fd(block)} {
      sched_read_file $chan $fid $self
    }
  }
  if {[lsearch $event write] >= 0} {
    set fd(watch_write) 1
    chan postevent $self write
  }
}

proc handle_seek {chan fid self off base} {
  upvar $self fd
  switch $base {
    start { set fd(off) $off }
    current { incr fd(off) $off }
    end {
      send/recv $chan stat [list $fid] {total fsize ftype fdev fqid_type
                                        fqid_ver fqid_path fmode fatime
                                        fmtime flen fname fuid fgid fmuid}
      set fd(off) $flen
    }
  }
  return $fd(off)
}

proc handle_blocking {chan fid self mode} {
  upvar $self fd
  set fd(block) $mode
}

proc chan_handle {chan fid command self args} {
  set fd [namespace current]::file/$self
  global $fd
  switch $command {
    finalize {
      unset $fd
      send/recv $chan clunk $fid
      rm_id fid $fid $chan
    }
    default { eval [list handle_$command $chan $fid $fd] $args }
  }
}

proc chan_from_fid {chan fid mode} {
  global [namespace current]::chan_open_modes
  chan create $chan_open_modes($mode) \
              [list [namespace current]::chan_handle $chan $fid]
}

##
## COMMANDS 
## 

proc auth {chan user name code} {
  set afid [new_id fid $chan]
  send/recv $chan auth [list $afid $user $name] {qid_type qid_ver qid_path}
  set table [list %f $afid %t $qid_type %v $qid_ver %p $qid_path]]
  set cmd [string map $code $table]
  eval $cmd
}

proc attach {chan args} {
  global [namespace current]::NOFID tcl_platform

  named $args [list -user $tcl_platform(user) \
                    -name "" \
                    -afid $NOFID \
                    -command {}]

  set fid [new_id fid $chan]
  send/recv $chan attach [list $fid $(-afid) $(-user) $(-name)] \
                         {qid_type qid_ver qid_path}
  if {$(-command) != ""} {
    set mapping [list %f $fid %t $qid_type %v $qid_ver %p $qid_path]]
    set cmd [string map $mapping $(-command)]
    eval $cmd
  }

  return $fid
}

proc walk {chan from_fid fid path} {
  global [namespace current]::iounit/$chan
  set iounit [set [namespace current]::iounit/$chan]
  set hdrsize [expr {4 + 1 + 2 + 4 + 4 + 2}]
  set size 0
  set num 0
  set buf ""
  #DBG "(walk) path: '$path'"
  if {$path eq ""} {
    #DBG "(walk) walking to root"
    send/recv $chan walk [list $from_fid $fid 0 ""] {qids}
  } else {
    foreach f [file split $path] {
      #DBG "(walk) walking to: $f"
      set str [encoding convertto utf-8 $f]
      set len [string length $str]
      if {[expr {$size + 2 + $len + $hdrsize < $iounit}]} {
        append buf [binary format sa$len $len $str]
        incr size [expr {2 + $len}]
        incr num
      } else {
        send/recv $chan walk [list $from_fid $fid $num $buf] {qids}
        set fid $newfid
        set size 0
        set num 0
        set buf ""
      }
    }
    if {$size > 0} {
      send/recv $chan walk [list $from_fid $fid $num $buf] {qids}
    }
  }
}

proc walk_fid {chan from_fid path} {
  set fid [new_id fid $chan]
  if {[catch [list walk $chan $from_fid $fid $path]]} {
    rm_id fid $fid $chan
    return -1
  } else {
    return $fid
  }
}

proc create_file {chan root_fid name mode perm} {
  global [namespace current]::QDIR
  set fid [walk_fid $chan $root_fid [file dirname $name]]
  if {$fid >= 0} {
    send/recv $chan stat [list $fid] {total fsize ftype fdev fqid_type
                                      fqid_ver fqid_path fmode fatime
                                      fmtime flen fname fuid fgid fmuid}
    if {[expr {$fqid_type & $QDIR}]} {
      send/recv $chan create [list $fid [file tail $name] $perm $mode] \
                             {qid iounit}
      set ret $fid
    } else {
      rm_id fid $fid $chan
      return -code error "couldn't create \"$name\""
    }
  } else {
    return -code error "couldn't create \"$name\""
  }
  return $fid
}

proc open_file {chan root_fid name {mode r} {perm 0644}} {
  global [namespace current]::open_modes
  set ret ""
  set binary ""
  if {$mode eq ""} {
    set mode r
  }
  if {[string match *b $mode]} {
    set binary b
    set mode [string range $mode 0 end-1]
  }
  set fid [walk_fid $chan $root_fid $name]
  if {$fid < 0} {
    if {[string match {[aw]*} $mode]} {
      set fid [create_file $chan $root_fid $name $open_modes($mode) $perm]
      set ret [chan_from_fid $chan $fid "$mode$binary"]
    } else {
      return -code error "couldn't open \"$name\": no such file or directory"
    }
  } else {
    send/recv $chan stat [list $fid] {total fsize ftype fdev fqid_type
                                      fqid_ver fqid_path fmode fatime
                                      fmtime flen fname fuid fgid fmuid}
    send/recv $chan open [list $fid $open_modes($mode)] {qid iounit}
    set ret [chan_from_fid $chan $fid "$mode$binary"]
  }
  return $ret
}

proc read_dir {chan root_fid name {command ""}} {
  set f [open_file $chan $root_fid $name]
  fconfigure $f -translation binary -encoding binary
  set ret [list]
  while {1} {
    set data [read $f]
    if {$data eq ""} {
      break
    }
    while {[string length $data]} {
      decstat $data {fsize ftype fdev fqid_type fqid_ver fqid_path fmode
                     fatime fmtime flen fname fuid fgid fmuid}
      #DBG "read_dir flen: $flen name: $fname uid: $fuid"
      set data [string range $data [expr {$fsize + 2}] end]
      if {$command eq ""} {
        lappend ret $fname
      } else {
        set map [list %n "{$fname}" %t $fqid_type %m $fmode]
        lappend ret [eval [string map $map $command]]
      }
    }
  }
  return $ret
}

#
# VFS
#

proc vfs_access {chan root_fid root name mode} {
  set fid [walk_fid $chan $root_fid $name]
  set ret 0
  if {$fid >= 0} {
    send/recv $chan stat [list $fid] {total fsize ftype fdev fqid_type
                                      fqid_ver fqid_path fmode fatime
                                      fmtime flen fname fuid fgid fmuid}
    rm_id fid $fid $chan
    #DBG "(vfs/access) file.mode: $fmode mode: $mode"
    set ret [expr {($fmode & $mode) == $mode}]
  } else {
  }
  #DBG "(vfs/access) ret: $ret"
  return $ret
}

proc vfs_createdirectory {chan root_fid root name} {
  global [current namespace]::QDIR
  set fid [create_file chan $root_fid $name 0 [expr {0777 | $QDIR}]]
  rm_id fid $fid $chan
}

proc vfs_deletefile {chan root_fid root name} {
  set fid [walk_fid $chan $root_fid $name]
  if {$fid >= 0} {
    send/recv $chan [list $fid] {}
    rm_id fid $fid $chan
  }
}

proc vfs_fileattributes {chan root_fid root name {index {}} {value {}}} {
  return {}
}

proc vfs_matchindirectory {chan root_fid root name pattern types} {
  set show_dirs [vfs::matchDirectories $types]
  set show_files [vfs::matchFiles $types]
  global [namespace current]::DMDIR
  set ret [list]
  #DBG "(match) dirs: $show_dirs files: $show_files"
  if {$pattern eq ""} {
    set stat [vfs_stat $chan $root_fid $name]
    set type 
    switch [dict get $stat type] {
      file {
        if {$show_files} {
          lappend ret $root
        }
      }
      directory {
        if {$show_dirs} {
          lappend ret $root
        }
      }
    }
    lappend ret 
  } else {
    foreach ent [read_dir $chan $root_fid $name {list %n %m}] {
      lassign $ent file type
      if {[string match $pattern $file]} {
        if {[expr {$type & $DMDIR}]} {
          if {$show_dirs} {
            lappend ret [file join $root $file]
          }
        } elseif {$show_files} {
          lappend ret [file join $root $file]
        }
      }
    }
  }
  return $ret
}

proc vfs_open {chan root_fid root name mode perm} {
  return [open_file $chan $root_fid $name $mode $perm]
}

proc vfs_removedirectory {chan root_fid root name recursive} {
  if {$recursive} {
    vfs_delete_file $chan $root_fid $name
  } else {
    if {[read_dir $chan $root_fid $name {list %n %m}] eq ""} {
      vfs_delete_file $chan $root_fid $name
    } else {
      return -code error EEXIST
    }
  }
}

proc vfs_stat {chan root_fid root name} {
  global [namespace current]::DMDIR
  set fid [walk_fid $chan $root_fid $name]
  set ret [list]
  if {$fid >= 0} {
    send/recv $chan stat [list $fid] {total fsize ftype fdev fqid_type
                                      fqid_ver fqid_path fmode fatime
                                      fmtime flen fname fuid fgid fmuid}
    rm_id fid $fid $chan
    if {[expr {$fmode & $DMDIR}]} {
      set type directory
    } else {
      set type file
    }
    set ret [list dev -1 \
                  mode [expr {$fmode & 0777}] \
                  nlink 1 \
                  uid -1 \
                  gid -1 \
                  atime $fatime \
                  mtime $fmtime \
                  ctime $fmtime \
                  type $type]
    #DBG "(vfs/stat) name: $fname stat: $ret"
  }
  return $ret
}

proc vfs_utime {chan root_fid root name actime mtime} {
  set fid [walk_fid $chan $root_fid $name]
  if {$fid >= 0} {
    set n1 [expr {2 + 2 + 4 + 1 + 4 + 8 + 4}]
    set total [expr {$n1 + 8 + 2 + 2 + 2 + 2}]
    set buf [binary format $stat c${nsize}iu1iu1iu1iu1su1su1su1su1
                                 [lrepeat $n1 0xff]
                                 $actime $mtime
                                 0xffffffff 0xffffffff
                                 0 0 0 0]
    send/recv $chan wstat [list $fid $buf] 
    rm_id fid $fid $chan
  }
}

proc vfs_cmd {chan root_fid cmd root rel path args} {
  #DBG "(vfs/cmd) cmd: $cmd"
  #DBG "          root: '$root'"
  #DBG "          rel: '$rel'"
  #DBG "          path: '$path'"
  #DBG "          args: '$args'"
  eval [list vfs_$cmd $chan $root_fid $path $rel] $args
}

proc file_stat {mnt name} {
  set mount [namespace current]::mount/$mnt
  upvar #0 $mount m
  set ret {}
  if {[info exists m(chan)] && [info exists m(root_fid)] && $m(chan) ne ""} {
    set chan $m(chan)
    set root_fid $m(root_fid)
    set fid [walk_fid $chan $root_fid $name]
    if {$fid >= 0} {
      send/recv $chan stat [list $fid] {total fsize ftype fdev fqid_type
                                        fqid_ver fqid_path fmode fatime
                                        fmtime flen fname fuid fgid fmuid}
      rm_id fid $fid $chan
      set ret [list -dev $fdev \
                    -mode [expr {$fmode & 0777}] \
                    -nlink 1 \
                    -uid $fuid \
                    -gid $fgid \
                    -atime $fatime \
                    -mtime $fmtime \
                    -ctime $fmtime \
                    -fmuid $fmuid]
    }
  }
  return $ret
}

proc mount {chan path args} {
  set mount [namespace current]::mount/$path
  global $mount
  if {[info exists $mount]} {
    incr [set mount](refcount)
  } else {
    set [set mount](refcount) 1 
    set [set mount](chan) $chan
  }
  set ids [namespace current]::tag/$chan
  global $ids
  if {![info exists $ids]} {
    9p::start $chan
  }
  set fid [eval [list attach $chan] $args]
  if {$fid >= 0} {
    set [set mount](root_fid) $fid
    ::vfs::filesystem mount -volume $path \
                            [list [namespace current]::vfs_cmd $chan $fid]
  }
}

proc umount {path} {
  set mount [namespace current]::mount/$path
  global $mount
  if {[info exists $mount]} {
    if {[set [set mount](refcount)] > 0} {
      incr [set mount](refcount) -1
      if {[set [set mount](refcount)] eq 0} {
        stop [set [set mount](chan)]
        unset $mount
      }
    }
  }
}
}

package provide 9p 0.1
