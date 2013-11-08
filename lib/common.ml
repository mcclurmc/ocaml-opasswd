let get_password name =
  if Shadow.shadow_enabled ()
  then Shadow.(with_lock (fun () ->
    match getspnam name with
    | None -> None
    | Some sp -> Some sp.passwd))
  else match Passwd.getpwnam name with
    | None -> None
    | Some pw -> Some pw.Passwd.passwd

let put_password name cipher =
  if Shadow.shadow_enabled ()
  then Shadow.(with_lock (fun () ->
    match getspnam name with
    | None -> ()
    | Some sp ->
       if cipher <> sp.passwd
       then begin
           get_db ()
           |> fun db -> update_db db { sp with passwd = cipher }
                        |> write_db
         end))
  else Passwd.(
    match getpwnam name with
    | None -> ()
    | Some pw ->
       if cipher <> pw.passwd
       then begin
           get_db ()
           |> fun db -> update_db db { pw with passwd = cipher }
           |> write_db
         end)

let unshadow () =
  if Shadow.shadow_enabled ()
  then begin
    let shadow_db = Shadow.(with_lock get_db)
    and passwd_db = Passwd.get_db () in
    List.map2
      (fun pw sp -> { pw with Passwd.passwd = sp.Shadow.passwd })
      passwd_db shadow_db
    |> Passwd.db_to_string
  end
  else Passwd.(get_db () |> db_to_string)

(* Local Variables: *)
(* indent-tabs-mode: nil *)
(* End: *)
