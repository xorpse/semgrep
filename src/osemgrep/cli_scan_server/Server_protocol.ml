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
   JSON-RPC 2.0 protocol implementation for the scan server.

   This module handles parsing and formatting of JSON-RPC messages,
   including requests, responses, and error handling.

   Reference: https://www.jsonrpc.org/specification
*)

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

(* JSON-RPC 2.0 error codes *)
module Error_code = struct
  let parse_error = -32700
  let invalid_request = -32600
  let method_not_found = -32601
  let invalid_params = -32602
  let internal_error = -32603
  (* Server errors: -32000 to -32099 *)
  let scan_error = -32001
  let session_not_found = -32002
  let timeout_error = -32003
end

(* Request ID can be string, number, or null *)
type request_id =
  | String_id of string
  | Int_id of int
  | Null_id

(* A JSON-RPC request *)
type request = {
  id : request_id;
  method_ : string;
  params : Yojson.Safe.t option;
}

(* A JSON-RPC error *)
type error = {
  code : int;
  message : string;
  data : Yojson.Safe.t option;
}

(* A JSON-RPC response *)
type response = {
  id : request_id;
  result : (Yojson.Safe.t, error) Result.t;
}

(* Scan request parameters *)
type scan_params = {
  content : string;
  filename : string;
  language : string;
  rules : Yojson.Safe.t option;  (* Inline rules as JSON *)
  session_id : string option;    (* Reference to preloaded session *)
}

(* Create-session request parameters *)
type create_session_params = {
  session_id : string;
  rules_file : string option;
  rules_json : Yojson.Safe.t option;  (* Rules directly as JSON *)
}

(* Destroy-session request parameters *)
type destroy_session_params = {
  session_id : string;
}

(* Scan result match *)
type scan_match = {
  rule_id : string;
  path : string;
  start_line : int;
  start_col : int;
  end_line : int;
  end_col : int;
  message : string;
  severity : string;
  extra : Yojson.Safe.t;
}

(* Scan result *)
type scan_result = {
  matches : scan_match list;
  errors : string list;
}

(*****************************************************************************)
(* Parsing *)
(*****************************************************************************)

let request_id_of_json (json : Yojson.Safe.t) : request_id =
  match json with
  | `String s -> String_id s
  | `Int i -> Int_id i
  | `Null -> Null_id
  | _ -> raise (Invalid_argument "Invalid request id type")

let request_id_to_json (id : request_id) : Yojson.Safe.t =
  match id with
  | String_id s -> `String s
  | Int_id i -> `Int i
  | Null_id -> `Null

let parse_request (json_str : string) : (request, error) Result.t =
  try
    let json = Yojson.Safe.from_string json_str in
    match json with
    | `Assoc fields ->
        (* Check jsonrpc version *)
        (match List.assoc_opt "jsonrpc" fields with
         | Some (`String "2.0") -> ()
         | _ ->
             raise (Invalid_argument "Missing or invalid jsonrpc version"));
        (* Get method *)
        let method_ =
          match List.assoc_opt "method" fields with
          | Some (`String m) -> m
          | _ -> raise (Invalid_argument "Missing or invalid method")
        in
        (* Get id (required for requests) *)
        let id =
          match List.assoc_opt "id" fields with
          | Some id_json -> request_id_of_json id_json
          | None -> Null_id
        in
        (* Get params (optional) *)
        let params = List.assoc_opt "params" fields in
        Ok { id; method_; params }
    | _ ->
        Error {
          code = Error_code.invalid_request;
          message = "Request must be a JSON object";
          data = None;
        }
  with
  | Yojson.Json_error msg ->
      Error {
        code = Error_code.parse_error;
        message = Printf.sprintf "Parse error: %s" msg;
        data = None;
      }
  | Invalid_argument msg ->
      Error {
        code = Error_code.invalid_request;
        message = msg;
        data = None;
      }

let parse_scan_params (params : Yojson.Safe.t option) : (scan_params, error) Result.t =
  match params with
  | None ->
      Error {
        code = Error_code.invalid_params;
        message = "Missing params for scan request";
        data = None;
      }
  | Some (`Assoc fields) ->
      (try
         let content =
           match List.assoc_opt "content" fields with
           | Some (`String s) -> s
           | _ -> raise (Invalid_argument "Missing or invalid 'content' parameter")
         in
         let filename =
           match List.assoc_opt "filename" fields with
           | Some (`String s) -> s
           | _ -> raise (Invalid_argument "Missing or invalid 'filename' parameter")
         in
         let language =
           match List.assoc_opt "language" fields with
           | Some (`String s) -> s
           | _ -> raise (Invalid_argument "Missing or invalid 'language' parameter")
         in
         let rules = List.assoc_opt "rules" fields in
         let session_id =
           match List.assoc_opt "session_id" fields with
           | Some (`String s) -> Some s
           | Some `Null | None -> None
           | _ -> raise (Invalid_argument "Invalid 'session_id' parameter")
         in
         Ok { content; filename; language; rules; session_id }
       with Invalid_argument msg ->
         Error {
           code = Error_code.invalid_params;
           message = msg;
           data = None;
         })
  | Some _ ->
      Error {
        code = Error_code.invalid_params;
        message = "Params must be a JSON object";
        data = None;
      }

let parse_create_session_params (params : Yojson.Safe.t option) : (create_session_params, error) Result.t =
  match params with
  | None ->
      Error {
        code = Error_code.invalid_params;
        message = "Missing params for create-session request";
        data = None;
      }
  | Some (`Assoc fields) ->
      (try
         let session_id =
           match List.assoc_opt "session_id" fields with
           | Some (`String s) -> s
           | _ -> raise (Invalid_argument "Missing or invalid 'session_id' parameter")
         in
         let rules_file =
           match List.assoc_opt "rules_file" fields with
           | Some (`String s) -> Some s
           | Some `Null | None -> None
           | _ -> raise (Invalid_argument "Invalid 'rules_file' parameter")
         in
         let rules_json = List.assoc_opt "rules" fields in
         (* Must have either rules_file or rules_json *)
         if Option.is_none rules_file && Option.is_none rules_json then
           raise (Invalid_argument "Must specify either 'rules_file' or 'rules'");
         Ok { session_id; rules_file; rules_json }
       with Invalid_argument msg ->
         Error {
           code = Error_code.invalid_params;
           message = msg;
           data = None;
         })
  | Some _ ->
      Error {
        code = Error_code.invalid_params;
        message = "Params must be a JSON object";
        data = None;
      }

let parse_destroy_session_params (params : Yojson.Safe.t option) : (destroy_session_params, error) Result.t =
  match params with
  | None ->
      Error {
        code = Error_code.invalid_params;
        message = "Missing params for destroy-session request";
        data = None;
      }
  | Some (`Assoc fields) ->
      (try
         let session_id =
           match List.assoc_opt "session_id" fields with
           | Some (`String s) -> s
           | _ -> raise (Invalid_argument "Missing or invalid 'session_id' parameter")
         in
         Ok { session_id }
       with Invalid_argument msg ->
         Error {
           code = Error_code.invalid_params;
           message = msg;
           data = None;
         })
  | Some _ ->
      Error {
        code = Error_code.invalid_params;
        message = "Params must be a JSON object";
        data = None;
      }

(*****************************************************************************)
(* Formatting *)
(*****************************************************************************)

let error_to_json (err : error) : Yojson.Safe.t =
  let base = [
    ("code", `Int err.code);
    ("message", `String err.message);
  ] in
  let with_data =
    match err.data with
    | Some d -> base @ [("data", d)]
    | None -> base
  in
  `Assoc with_data

let scan_match_to_json (m : scan_match) : Yojson.Safe.t =
  `Assoc [
    ("rule_id", `String m.rule_id);
    ("path", `String m.path);
    ("start", `Assoc [
        ("line", `Int m.start_line);
        ("col", `Int m.start_col);
      ]);
    ("end", `Assoc [
        ("line", `Int m.end_line);
        ("col", `Int m.end_col);
      ]);
    ("extra", `Assoc [
        ("message", `String m.message);
        ("severity", `String m.severity);
        ("metadata", m.extra);
      ]);
  ]

let scan_result_to_json (result : scan_result) : Yojson.Safe.t =
  `Assoc [
    ("matches", `List (List.map scan_match_to_json result.matches));
    ("errors", `List (List.map (fun s -> `String s) result.errors));
  ]

let format_response (resp : response) : string =
  let result_json =
    match resp.result with
    | Ok r -> [("result", r)]
    | Error e -> [("error", error_to_json e)]
  in
  let json = `Assoc ([
      ("jsonrpc", `String "2.0");
      ("id", request_id_to_json resp.id);
    ] @ result_json)
  in
  Yojson.Safe.to_string json

let make_success_response (id : request_id) (result : Yojson.Safe.t) : response =
  { id; result = Ok result }

let make_error_response (id : request_id) (err : error) : response =
  { id; result = Error err }

let make_method_not_found (id : request_id) (method_ : string) : response =
  make_error_response id {
    code = Error_code.method_not_found;
    message = Printf.sprintf "Method not found: %s" method_;
    data = None;
  }

let make_internal_error (id : request_id) (msg : string) : response =
  make_error_response id {
    code = Error_code.internal_error;
    message = msg;
    data = None;
  }

let make_scan_error (id : request_id) (msg : string) : response =
  make_error_response id {
    code = Error_code.scan_error;
    message = msg;
    data = None;
  }

let make_session_not_found (id : request_id) (session_id : string) : response =
  make_error_response id {
    code = Error_code.session_not_found;
    message = Printf.sprintf "Session not found: %s" session_id;
    data = None;
  }

let make_timeout_error (id : request_id) : response =
  make_error_response id {
    code = Error_code.timeout_error;
    message = "Scan timed out";
    data = None;
  }
