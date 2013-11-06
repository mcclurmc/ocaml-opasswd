open Unix

open OPasswd

let tmp_shadow_file = Unix.getcwd () ^ "/dummy-shadow"
let tmp_passwd_file = Unix.getcwd () ^ "/dummy-passwd"

let chpwd_test name =
  let open Shadow in

  Printf.printf "Getting password for %s\n" name;

  Printf.printf "Lock acquired? %b\n" (lckpwdf ());
  let sp = getspnam name in
  Printf.printf "Lock released? %b\n" (ulckpwdf ());

  Printf.printf "%s's passwd: %s\n" name sp.pwd;
  Printf.printf "%s's lstchg: %Ld\n" name sp.last_chg;
  Printf.printf "%s's min: %Ld\n" name sp.min;
  Printf.printf "%s's max: %Ld\n" name sp.max;
  Printf.printf "%s's flag: %Ld\n" name sp.flag;

  Printf.printf "setting %s's password to 'foobar'\n" name;
  let sp = { sp with pwd = "foobar" } in

  let f = open_in tmp_shadow_file in
  begin
    try
      let l = input_line f in
      print_endline "we wrote:";
      print_endline l
    with _ ->
      Printf.printf "Couldn't read file '%s'\n" tmp_shadow_file
  end;
  close_in f;

  sp

let create_file file =
  openfile file [ O_RDONLY; O_CREAT ] 0o666 |> close

let test_shadow () =
  create_file tmp_shadow_file;
  let name = "backup" in
  try
    Shadow.with_lock Shadow.(fun () ->
      let sp = getspnam name in
      let db = get_db () in
      let db = update_db db { sp with pwd = "foobar" } in
    (* print_endline @@ String.concat "\n" @@ List.map to_string db; *)
      write_db ~file:tmp_shadow_file db)
  with _ ->
    print_endline "Couldn't acquire lock, must be root"

let test_passwd () =
  create_file tmp_passwd_file;
  let open Passwd in
  let name = "backup" in
  let pw = getpwnam name in
  let db = get_db () in
  let db = update_db db { pw with passwd = "barfoo" } in
  (* print_endline @@ String.concat "\n" @@ List.map to_string db; *)
  write_db ~file:tmp_passwd_file db

let test_unshadow () =
  try
    let passwd = Common.unshadow () in
    print_endline passwd
  with _ ->
    print_endline "Couldn't acquire lock, must be root"

(* Try to blow up GC *)
let test_gc () =
  let name = "backup"
  and iter = 1000000 in

  (* Lower GC heap sizes, set verbose *)
  (* Gc.set { (Gc.get ()) with *)
  (*   Gc.verbose = 0x3FF; *)
  (*   Gc.minor_heap_size = 1; *)
  (* }; *)

  Printf.printf "Testing Passwd.getpwnam on %d iterations\n" iter;
  Pervasives.(flush stdout);
  for i = 1 to iter do
    ignore (Passwd.getpwnam name)
  done;

  Printf.printf "Testing Shadow.getspnam on %d iterations\n" iter;
  try
    for i = 1 to iter do
      ignore Shadow.(with_lock (fun () -> getspnam name))
    done;
  with _ ->
    print_endline "Couldn't acquire lock, must be root";

  ()

let test_ctypes () =
  let open Passwd in
  (* let pw = getpwnam' "backup" in *)
  (* let pass = getf !@pw pw_passwd in *)
  (* print_endline ("Password for backup: " ^ pass); *)
  let pw = getpwnam "backup" in
  Printf.printf "Password for backup: %s\n" pw.passwd;
  Printf.printf "UID for backup: %d\n" pw.uid

let main =
  test_shadow (); print_endline "* finished test_shadow"; flush Pervasives.stdout;
  test_passwd (); print_endline "* finished test_passwd"; flush Pervasives.stdout;
  test_passwd (); print_endline "* finished test_passwd"; flush Pervasives.stdout;
  test_unshadow (); print_endline "* finished test_unshadow"; flush Pervasives.stdout;
  (* test_gc (); *)
  test_ctypes (); print_endline "* finished test_ctypes"; flush Pervasives.stdout;
  ()

(* Local Variables: *)
(* indent-tabs-mode: nil *)
(* End: *)
