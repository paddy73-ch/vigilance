# Vigilance: read-only check before removing obsolete packages (sh, run as root on the target).
# Arguments: package names. Prints one section per package:
#   ##PKG <name>
#   ##SIM <Purg|Remv> <package>          what `apt-get -s purge <name>` would remove
#   ##SIMERR <text>                      simulation failed
#   ##USE <pid> <command>                running process (same mount namespace) maps a library of the package
#   ##EXT <path>                         file under /usr/local or /opt (not managed by dpkg) references a library soname
#   ##LIBS <n>                           number of shared libraries in the package (0: no usage check possible)
#   ##NOROOT                             (once) not run as root: processes of other users cannot be checked
#   ##KERNEL <release>                   (once) running kernel, from uname -r
#   ##AVAIL yes|no                       installed version still available from a package source (can be reinstalled)
# Nothing is changed on the host: apt-get runs with -s (simulation) and without its planner log,
# everything else only reads.
LC_ALL=C; export LC_ALL
self_ns=$(readlink /proc/1/ns/mnt 2>/dev/null)
[ "$(id -u)" = 0 ] || echo "##NOROOT"
echo "##KERNEL $(uname -r)"
for p in "$@"; do
  echo "##PKG $p"
  # Dir::Log::Planner=/dev/null: even a simulation would otherwise rewrite /var/log/apt/eipp.log.xz
  out=$(apt-get -s -o Debug::NoLocking=1 -o Dir::Log::Planner=/dev/null purge "$p" 2>&1); rc=$?
  if [ $rc -ne 0 ]; then
    echo "##SIMERR $(printf '%s' "$out" | grep -E '^E:' | head -n 2 | tr '\n' ' ')"
  else
    printf '%s\n' "$out" | awk '/^(Purg|Remv) /{print "##SIM " $1 " " $2}'
  fi
  # Version table of `apt-cache policy`: sources listed under the installed version (***)
  apt-cache policy "$p" 2>/dev/null | awk '
    /^ \*\*\* / { inst = 1; next }
    inst && /^        -?[0-9]+ / { if ($0 !~ /\/var\/lib\/dpkg\/status/) avail = 1; next }
    inst && /^     [^ ]/ { inst = 0 }
    END { print "##AVAIL " (avail ? "yes" : "no") }'
  files=$(dpkg -L "$p" 2>/dev/null | grep -E '/[^/]+\.so(\.[0-9]+)*$')
  echo "##LIBS $(printf '%s' "$files" | grep -c .)"
  [ -n "$files" ] || continue
  libs=$(printf '%s\n' "$files" | while read -r f; do [ -e "$f" ] && readlink -f "$f"; done | sort -u)
  [ -n "$libs" ] || continue
  for m in $(grep -lF "$libs" /proc/[0-9]*/maps 2>/dev/null); do
    pid=${m#/proc/}; pid=${pid%/maps}
    [ "$(readlink /proc/$pid/ns/mnt 2>/dev/null)" = "$self_ns" ] || continue
    echo "##USE $pid $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120)"
  done
  # Only real sonames (lib*.so.N); generic names like Util.so (Perl modules) would match anything
  sonames=$(printf '%s\n' "$files" | sed 's|.*/||' | grep -E '^lib.+\.so\.[0-9]' | sort -u)
  [ -n "$sonames" ] || continue
  for d in /usr/local /opt; do
    [ -d "$d" ] || continue
    find "$d" -xdev -type f -size -64M \( -perm -u+x -o -name '*.so*' \) 2>/dev/null | head -n 5000 \
      | while read -r f; do
          [ "$(head -c 4 "$f" 2>/dev/null | tr -d '\177')" = "ELF" ] || continue
          grep -qF "$sonames" "$f" 2>/dev/null && echo "##EXT $f"
        done | head -n 20
  done
done
