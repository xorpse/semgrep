(*
   Copyright (c) 2025 Semgrep Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   version 2.1 as published by the Free Software Foundation.

   This library is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
   LICENSE for more details.
*)

(*****************************************************************************)
(* Prelude *)
(*****************************************************************************)
(*
   Handler for scan requests in the scan server.

   This module:
   - Parses in-memory content using the string-based parsing API
   - Runs rules against the parsed AST
   - Converts matches to the JSON-RPC response format
*)

(*****************************************************************************)
(* Helpers *)
(*****************************************************************************)

(* Parse language string to Lang.t *)
let parse_language (lang_str : string) : (Lang.t, string) Result.t =
  try
    Ok (Lang.of_string lang_str)
  with
  | _ ->
      (* Try lowercase version *)
      try
        Ok (Lang.of_string (String.lowercase_ascii lang_str))
      with
      | _ -> Error (Printf.sprintf "Unsupported language: %s" lang_str)

(* Parse and resolve names from a string, returning AST and skipped tokens *)
let parse_content (lang : Lang.t) (fpath : Fpath.t) (content : string)
    : (AST_generic.program * Tok.location list, string) Result.t =
  try
    let result = Parse_target.parse_and_resolve_name_from_string lang fpath content in
    Ok (result.ast, result.skipped_tokens)
  with
  | e ->
      Error (Printf.sprintf "Parse error: %s" (Printexc.to_string e))

(* Convert a Core_match.t to a Server_protocol.scan_match *)
let match_to_scan_match (pm : Core_match.t) : Server_protocol.scan_match =
  let loc = pm.range_loc in
  let start_loc, end_loc = loc in
  let rule_id = Rule_ID.to_string pm.rule_id.id in
  let path = Fpath.to_string pm.path.internal_path_to_content in
  let message =
    match pm.rule_id.message with
    | "" -> "Match found"
    | msg -> msg
  in
  let severity =
    match pm.severity_override with
    | Some sev -> Rule.show_severity sev
    | None -> "WARNING"
  in
  let extra : Yojson.Safe.t =
    match pm.rule_id.metadata with
    | Some json -> (JSON.to_yojson json :> Yojson.Safe.t)
    | None -> `Assoc []
  in
  {
    Server_protocol.rule_id;
    path;
    start_line = start_loc.pos.line;
    start_col = start_loc.pos.column;
    end_line = end_loc.pos.line;
    end_col = end_loc.pos.column;
    message;
    severity;
    extra;
  }

(*****************************************************************************)
(* Main scanning function *)
(*****************************************************************************)

type scan_caps = < Cap.time_limit >

(* Scan in-memory content with the given rules *)
let scan_content
    (caps : < scan_caps ; .. >)
    ~(timeout : float)
    ~(rules : Rule.t list)
    ~(content : string)
    ~(filename : string)
    ~(lang : Lang.t)
    : Server_protocol.scan_result =
  (* Create a virtual file path for the content *)
  let fpath = Fpath.v filename in

  (* Create an in-memory target *)
  let analyzer = Analyzer.of_lang lang in
  let target = Target.mk_in_memory_target ~name:filename ~content analyzer in

  (* Filter rules that apply to this language *)
  let applicable_rules =
    Core_scan.rules_for_analyzer ~combine_js_with_ts:false analyzer rules
  in

  if List.length applicable_rules = 0 then
    (* No applicable rules for this language *)
    { Server_protocol.matches = []; errors = [] }
  else begin
    (* Parse the content *)
    match parse_content lang fpath content with
    | Error msg ->
        { Server_protocol.matches = []; errors = [msg] }
    | Ok (ast, _skipped_tokens) ->
        (* Create the Xtarget with a pre-parsed AST *)
        let lazy_ast = Lazy_safe.from_val (ast, []) in
        let xtarget = Xtarget.resolve_with_ast lazy_ast target in

        (* Create xconfig *)
        let xconf : Match_env.xconfig = {
          config = Rule_options.default;
          nested_formula = false;
          matching_explanations = false;
          filter_irrelevant_rules = Match_env.NoPrefiltering;
        } in

        (* Set up timeout *)
        let timeout_config : Match_rules.timeout_config option =
          Some {
            timeout;
            threshold = 0;  (* No threshold for server mode *)
            caps = (caps :> < Cap.time_limit >);
            eio = true;  (* We're running under Eio *)
          }
        in

        (* Run the matching engine *)
        try
          let result : Core_result.matches_single_file =
            Match_rules.check
              ~matches_hook:Fun.id
              ~timeout:timeout_config
              xconf
              applicable_rules
              xtarget
          in

          (* Convert matches to the response format *)
          let matches =
            result.matches
            |> List.map match_to_scan_match
          in

          (* Convert errors to strings *)
          let errors =
            Core_error.ErrorSet.elements result.errors
            |> List.map (fun (err : Core_error.t) ->
                Printf.sprintf "%s: %s"
                  (Semgrep_output_v1_j.string_of_error_type err.typ)
                  err.msg)
          in

          { Server_protocol.matches; errors }
        with
        | Match_rules.File_timeout rule_ids ->
            let rule_id_strs = List.map Rule_ID.to_string rule_ids in
            let msg = Printf.sprintf "Scan timed out for rules: %s"
                (String.concat ", " rule_id_strs) in
            { Server_protocol.matches = []; errors = [msg] }
        | e ->
            let msg = Printf.sprintf "Match error: %s" (Printexc.to_string e) in
            { Server_protocol.matches = []; errors = [msg] }
  end

(*****************************************************************************)
(* Rule loading *)
(*****************************************************************************)

(* Load rules from a file *)
let load_rules_from_file (fpath : Fpath.t)
    : (Rule.t list, string) Result.t =
  try
    match Parse_rule.parse_and_filter_invalid_rules fpath with
    | Ok (rules, invalid_rules) ->
        if List.length invalid_rules > 0 then
          Logs.warn (fun m ->
              m "Loaded %d rules, %d invalid rules from %s"
                (List.length rules) (List.length invalid_rules)
                (Fpath.to_string fpath));
        Ok rules
    | Error err ->
        Error (Rule_error.show err)
  with
  | e ->
      Error (Printf.sprintf "Failed to load rules from %s: %s"
               (Fpath.to_string fpath) (Printexc.to_string e))

(* Parse rules from JSON *)
let parse_rules_from_json (json : Yojson.Safe.t)
    : (Rule.t list, string) Result.t =
  (* Write JSON to a temporary file and parse it *)
  (* This is not ideal, but Parse_rule expects a file path *)
  try
    let tmp_file = Filename.temp_file "semgrep_rules_" ".json" in
    let tmp_path = Fpath.v tmp_file in
    let content = Yojson.Safe.to_string json in
    Out_channel.with_open_bin tmp_file (fun oc ->
        Out_channel.output_string oc content);
    let result = load_rules_from_file tmp_path in
    Sys.remove tmp_file;
    result
  with
  | e ->
      Error (Printf.sprintf "Failed to parse rules from JSON: %s"
               (Printexc.to_string e))
