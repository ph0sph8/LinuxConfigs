    if(type(links_to) == 'string') then
      links_to = {links_to}
    end

    for _, v in ipairs(links_to) do
      stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'links_to', parsed['path_query']}, v)
    end
  end

  -- Save the pages it's linked from (we save these in the 'links_to' key, reversed)
  if(linked_from) then
    if(type(linked_from) == 'string') then
      linked_from = {linked_from}
    end

    for _, v in ipairs(linked_from) do
      stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'links_to', v}, parsed['path_query'])
    end
  end

  -- Save it as a content-type, if we have one
  if(contenttype) then
    stdnse.registry_add_array({parsed['host'] or host, 'www', parsed['port'] or port, 'content-type', contenttype}, parsed['path_query'])
  end
end

local unittest = require "unittest"
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

do
  local cookie_tests = {
    { -- #844
      " SESSIONID=IgAAABjN8b3xxxNsLRIiSpHLPn1lE=&IgAAAxxxMT6Bw==&Huawei USG6320&langfrombrows=en-US&copyright=2014;secure", {
        name = "SESSIONID",
        value = "IgAAABjN8b3xxxNsLRIiSpHLPn1lE=&IgAAAxxxMT6Bw==&Huawei USG6320&langfrombrows=en-US&copyright=2014",
        secure = true
      }
    },
    { -- #866
      " SID=c98fefa3ad659caa20b89582419bb14f; Max-Age=1200; Version=1", {
        name = "SID",
        value = "c98fefa3ad659caa20b89582419bb14f",
        ["max-age"] = "1200",
        version = "1"
      }
    },
    { -- #731
      "session_id=76ca8bc8c19;", {
        name = "session_id",
        value = "76ca8bc8c19"
        }
    },
    { -- #229
      "c1=aaa; path=/bbb/ccc,ddd/eee", {
        name = "c1",
        value = "aaa",
        path = "/bbb/ccc,ddd/eee"
      }
    },
  }

  for _, test in ipairs(cookie_tests) do
    local parsed = parse_set_cookie(test[1])
    test_suite:add_test(unittest.keys_equal(parsed, test[2], test[1]))
  end
end

return _ENV;
root@MSF-ATK:/usr/share/nmap/nselib# clear

root@MSF-ATK:/usr/share/nmap/nselib# nano http.lua 









































































  GNU nano 2.9.3                                                                                                                       http.lua                                                                                                                                 

---Implements the HTTP client protocol in a standard form that Nmap scripts can
-- take advantage of.
--
-- Because HTTP has so many uses, there are a number of interfaces to this
-- library.
--
-- The most obvious and common ones are simply <code>get</code>,
-- <code>post</code>, and <code>head</code>; or, if more control is required,
-- <code>generic_request</code> can be used. These functions take host and port
-- as their main parameters and they do what one would expect. The
-- <code>get_url</code> helper function can be used to parse and retrieve a full
-- URL.
--
-- HTTPS support is transparent. The library uses <code>comm.tryssl</code> to
-- determine whether SSL is required for a request.
--
-- These functions return a table of values, including:
-- * <code>status-line</code> - A string representing the status, such as "HTTP/1.1 200 OK", followed by a newline. In case of an error, a description will be provided in this line.
-- * <code>status</code> - The HTTP status value; for example, "200". If an error occurs during a request, then this value is going to be nil.
-- * <code>version</code> - HTTP protocol version string, as stated in the status line. Example: "1.1"
-- * <code>header</code> - An associative array representing the header. Keys are all lowercase, and standard headers, such as 'date', 'content-length', etc. will typically be present.
-- * <code>rawheader</code> - A numbered array of the headers, exactly as the server sent them. While header['content-type'] might be 'text/html', rawheader[3] might be 'Content-type: text/html'.
-- * <code>cookies</code> - A numbered array of the cookies the server sent. Each cookie is a table with the expected keys, such as <code>name</code>, <code>value</code>, <code>path</code>, <code>domain</code>, and <code>expires</code>. This table can be sent to the serv$
-- * <code>body</code> - The full body, as returned by the server. Chunked encoding is handled transparently.
-- * <code>fragment</code> - Partially received body (if any), in case of an error.
-- * <code>location</code> - A numbered array of the locations of redirects that were followed.
--
-- Many of the functions optionally allow an "options" input table, which can
-- modify the HTTP request or its processing in many ways like adding headers or
-- setting the timeout. The following are valid keys in "options"
-- (note: not all options will necessarily affect every function):
-- * <code>timeout</code>: A timeout used for socket operations.
-- * <code>header</code>: A table containing additional headers to be used for the request. For example, <code>options['header']['Content-Type'] = 'text/xml'</code>
-- * <code>content</code>: The content of the message. This can be either a string, which will be directly added as the body of the message, or a table, which will have each key=value pair added (like a normal POST request). (A corresponding Content-Length header will be$
-- * <code>cookies</code>: A list of cookies as either a string, which will be directly sent, or a table. If it's a table, the following fields are recognized: <code>name</code>, <code>value</code> and <code>path</code>. Only <code>name</code> and <code>value</code> fiel$
-- * <code>auth</code>: A table containing the keys <code>username</code> and <code>password</code>, which will be used for HTTP Basic authentication.
--   If a server requires HTTP Digest authentication, then there must also be a key <code>digest</code>, with value <code>true</code>.
--   If a server requires NTLM authentication, then there must also be a key <code>ntlm</code>, with value <code>true</code>.
-- * <code>bypass_cache</code>: Do not perform a lookup in the local HTTP cache.
-- * <code>no_cache</code>: Do not save the result of this request to the local HTTP cache.
-- * <code>no_cache_body</code>: Do not save the body of the response to the local HTTP cache.
-- * <code>any_af</code>: Allow connecting to any address family, inet or inet6. By default, these functions will only use the same AF as nmap.address_family to resolve names. (This option is a straight pass-thru to <code>comm.lua</code> functions.)
-- * <code>redirect_ok</code>: Closure that overrides the default redirect_ok used to validate whether to follow HTTP redirects or not. False, if no HTTP redirects should be followed. Alternatively, a number may be passed to change the number of redirects to follow.
--   The following example shows how to write a custom closure that follows 5 consecutive redirects, without the safety checks in the default redirect_ok:
--   <code>
--   redirect_ok = function(host,port)
--     local c = 5
--     return function(url)
--       if ( c==0 ) then return false end
--       c = c - 1
--       return true
--     end
--   end
--   </code>
--
-- If a script is planning on making a lot of requests, the pipelining functions
-- can be helpful. <code>pipeline_add</code> queues requests in a table, and
-- <code>pipeline_go</code> performs the requests, returning the results as an
-- array, with the responses in the same order as the requests were added.
-- As a simple example:
--<code>
--  -- Start by defining the 'all' variable as nil
--  local all = nil
--
--  -- Add two GET requests and one HEAD to the queue but these requests are
--  -- not performed yet. The second parameter represents the "options" table
--  -- (which we don't need in this example).
--  all = http.pipeline_add('/book',    nil, all)
--  all = http.pipeline_add('/test',    nil, all)
                                                                                                                              [ Read 2952 lines ]
^G Get Help       ^O Write Out      ^W Where Is       ^K Cut Text       ^J Justify        ^C Cur Pos        M-U Undo          M-A Mark Text     M-] To Bracket    M-▲ Previous      ^B Back           ^◀ Prev Word      ^A Home           ^P Prev Line      M-- Scroll Up
^X Exit           ^R Read File      ^\ Replace        ^U Uncut Text     ^T To Spell       ^_ Go To Line     M-E Redo          M-6 Copy Text     M-W WhereIs Next  M-▼ Next          ^F Forward        ^▶ Next Word      ^E End            ^N Next Line      M-+ Scroll Down

