#########################
# PHP Vulnerability Database
#
# Thanks to fluxreiners for his work in rips
#########################

import phply


#OS Command execution functions
F_COMMAND_EXEC = {
    'backsticks'                        : [0], #this is not supported yet, TODO:see how to parse with ply ?!!
    'exec'                              : [0],
    'expect_open'                       : [0],
    'popen'                             : [0],
    'pcntl_exec'                        : [0],
    'popen'                             : [0],
    'proc_open'                         : [0],
    'system'                            : [0],
    'shell_exec'                        : [0],
    'passthru'                          : [0],
    'w32api_invoke_function'            : [0],
    'w32api_register_function'          : [1],
    'mail'                              : [4]
        }

#Cross-site secripting, some of these method are transformed to the Echo class
#TODO: either transform all of these to Echo or find a cleaner way
F_XSS = {
    'echo'                              : [0],
    'print'                             : [1],
    'print_r'                           : [1],
    'exit'                              : [1],
    'die'                               : [1],
    'printf'                            : [0], #Not sure this is the correct format !!
    'vprintf'                           : [0],
    phply.phpast.Print                  : [0],
    phply.phpast.Echo                   : [0]
    }

#HTTP header injection
F_HTTP_HEADER_INJ = {
    'header'                             : [1],
    }

#Code execution
F_CODE_EXEC = {
		'array_diff_uassoc'	 			: [2],
		'array_diff_ukey'				: [2],
		'array_filter'					: [1],
		'array_intersect_uassoc'		: [2],
		'array_intersect_ukey'			: [2],
		'array_map'						: [0],
		'array_reduce'					: [1],
		'array_udiff'					: [2],
		'array_udiff_assoc'				: [2],
		'array_udiff_uassoc'			: [2,3],
		'array_uintersect'				: [2],
		'array_uintersect_assoc'		: [2],
		'array_uintersect_uassoc'		: [2,3],
		'array_walk'					: [1],
		'array_walk_recursive'			: [1],
		'assert' 						: [0],
		'assert_options'				: [0,1],
		'call_user_func'				: [0],
		'call_user_func_array'			: [0],
		'create_function' 				: [0,1],
		'dotnet_load'					: [0],
		'forward_static_call'			: [0],
		'forward_static_call_array'		: [0],
		'eio_busy'						: [2],
		'eio_chmod'						: [3],
		'eio_chown'						: [4],
		'eio_close'						: [2],
		'eio_custom'					: [0,1],
		'eio_dup2'						: [3],
		'eio_fallocate'					: [5],
		'eio_fchmod'					: [3],
		'eio_fchown'					: [4],
		'eio_fdatasync'					: [2],
		'eio_fstat'						: [2],
		'eio_fstatvfs'					: [2],
		'eval' 							: [0],
		'event_buffer_new'				: [1,2,3],
		'event_set'						: [3],
		'iterator_apply'				: [1],
		'mb_ereg_replace'				: [0,1],
		'mb_eregi_replace'				: [0,1],
		'ob_start'						: [0],
		'preg_filter'					: [0,1],
		'preg_replace'					: [0,1],
		'preg_replace_callback'			: [0,1],
		'register_shutdown_function'	: [0],
		'register_tick_function'		: [0],
		'runkit_method_add'				: [0,1,2,3],
		'runkit_method_copy'			: [0,1,2],
		'runkit_method_redefine'		: [0,1,2,3],
		'runkit_method_rename'			: [0,1,2],
		'runkit_function_add'			: [0,1,2],
		'runkit_function_copy'			: [0,1],
		'runkit_function_redefine'		: [0,1,2],
		'runkit_function_rename'		: [0,1],
		'session_set_save_handler'		: [0,1,2,3,4],
		'set_error_handler'				: [0],
		'set_exception_handler'			: [0],
		'spl_autoload'					: [0],
		'spl_autoload_register'			: [0],
		'sqlite_create_aggregate'		: [1,2,3],
		'sqlite_create_function'		: [1,2],
		'stream_wrapper_register'		: [1],
		'uasort'						: [1],
		'uksort'						: [1],
		'usort'							: [1],
		'yaml_parse'					: [3],
		'yaml_parse_file'				: [3],
		'yaml_parse_url'				: [3],
        phply.phpast.Eval               : [0]
        }

#File inclsuion (LFI & RFI
F_FILE_INCLUDE = {
		'include' 	 					: [0], #there is a sepcial class for this method phply.phpast.Include
		'include_once' 					: [0], #there is a sepcial class for this method phply.phpast.Include
		'parsekit_compile_file'			: [0],
		'php_check_syntax' 				: [0],
		'require' 						: [0], #there is a sepcial class for this method phply.phpast.Require
		'require_once' 					: [0], #there is a sepcial class for this method phply.phpast.Require
		'runkit_import'					: [0],
		'set_include_path' 				: [0],
		'virtual' 						: [0],
        phply.phpast.Include            : [0],
        phply.phpast.Require            : [0]
        }


#File manipulation
F_FILE_READ = {
		'bzread' 						: [0],
		'bzflush'						: [0],
		'dio_read'						: [0],
		'eio_readdir'					: [0],
		'fdf_open'						: [0],
		'file'							: [0],
		'file_get_contents'				: [0],
		'finfo_file'					: [0,1],
		'fflush'						: [0],
		'fgetc'							: [0],
		'fgetcsv'						: [0],
		'fgets'							: [0],
		'fgetss'						: [0],
		'fread'							: [0],
        'fopen'                         : [0],
		'fpassthru'						: [0,1],
		'fscanf'						: [0],
		'ftok'							: [0],
		'get_meta_tags'					: [0],
		'glob'							: [0],
		'gzfile'						: [0],
		'gzgetc'						: [0],
		'gzgets'						: [0],
		'gzgetss'						: [0],
		'gzread'						: [0],
		'gzpassthru'					: [0],
		'highlight_file'				: [0],
		'imagecreatefrompng'			: [0],
		'imagecreatefromjpg'			: [0],
		'imagecreatefromgif'			: [0],
		'imagecreatefromgd2'			: [0],
		'imagecreatefromgd2part'		: [0],
		'imagecreatefromgd'				: [0],
        'move_uploaded_file'            : [0,1],
		'opendir'						: [0],
		'parse_ini_file' 				: [0],
		'php_strip_whitespace'			: [0],
		'readfile'						: [0],
		'readgzfile'					: [0],
		'readlink'						: [0],
		'stat'						    : [0],
		'scandir'						: [0],
		'show_source'					: [0],
        'simplexml_load_file'           : [0],
		'stream_get_contents'			: [0],
		'stream_get_line'				: [0],
		'xdiff_file_bdiff'				: [0,1],
		'xdiff_file_bpatch'				: [0,1],
		'xdiff_file_diff_binary'		: [0,1],
		'xdiff_file_diff'				: [0,1],
		'xdiff_file_merge3'				: [0,1,2],
		'xdiff_file_patch_binary'		: [0,1],
		'xdiff_file_patch'				: [0,1],
		'xdiff_file_rabdiff'			: [0,1],
		'yaml_parse_file'				: [0],
		'zip_open'						: [0]
        }

F_DATABASE = {
	# Abstraction Layers
		'dba_open'	 					: [0],
		'dba_popen'						: [0],
		'dba_insert'					: [0,1],
		'dba_fetch'						: [0],
		'dba_delete'					: [0],
		'dbx_query'						: [1],
		'odbc_do'						: [1],
		'odbc_exec'						: [1],
		'odbc_execute'					: [1],
	# Vendor Specific
		'db1_exec' 						: [1],
        'db_query'                      : [0,1], #depending on vendor, DB handler and SQL query are reversed
		'db1_execute'					: [1],
		'fbsql_db_query'				: [1],
		'fbsql_query'					: [0],
		'ibase_query'					: [1],
		'ibase_execute'					: [0],
		'ifx_query'						: [0],
		'ifx_do'						: [0],
		'ingres_query'					: [1],
		'ingres_execute'				: [1],
		'ingres_unbuffered_query'		: [1],
		'msql_db_query'					: [1],
		'msql_query'					: [0],
		'msql'							: [1],
		'mssql_query'					: [0],
		'mssql_execute'					: [0],
		'mysql_db_query'				: [1],
		'mysql_query'					: [0],
		'mysql_unbuffered_query'		: [0],
		'mysqli_stmt_execute'			: [0],
		'mysqli_query'					: [1],
		'mysqli_real_query'				: [0],
		'mysqli_master_query'			: [1],
		'oci_execute'					: [0],
		'ociexecute'					: [0],
		'ovrimos_exec'					: [1],
		'ovrimos_execute'				: [1],
		'ora_do'						: [1],
		'ora_exec'						: [0],
		'pg_query'						: [1],
		'pg_send_query'					: [1],
		'pg_send_query_params'			: [1],
		'pg_send_prepare'				: [2],
		'pg_prepare'					: [2],
		'sqlite_open'					: [0],
		'sqlite_popen'					: [0],
		'sqlite_array_query'			: [0,1],
		'arrayQuery'					: [0,1],
		'singleQuery'					: [0],
		'sqlite_query'					: [0,1],
		'sqlite_exec'					: [0,1],
		'sqlite_single_query'			: [1],
		'sqlite_unbuffered_query'		: [0,1],
		'sybase_query'					: [0],
		'sybase_unbuffered_query'		: [0],
        #application specific
        'api_DB_query'                  : [0]
        }

# xpath injection
F_XPATH = {
		'xpath_eval' 					: [1],
		'xpath_eval_expression'			: [1],
		'xptr_eval'						: [1]
        }

# ldap injection
F_LDAP = {
		'ldap_add'	 					: [1,2],
		'ldap_delete'					: [1],
		'ldap_list'						: [2],
		'ldap_read'						: [2],
		'ldap_search'					: [2]
        }

# connection handling functions
F_CONNECT = {
		'curl_setopt'	 				: [1,2],
		'curl_setopt_array' 			: [1],
		'cyrus_query' 					: [1],
		'error_log'						: [2],
		'fsockopen'						: [0],
		'ftp_chmod' 					: [1,2],
		'ftp_exec'						: [1],
		'ftp_delete' 					: [1],
		'ftp_fget' 						: [2],
		'ftp_get'						: [1,2],
		'ftp_nlist' 					: [1],
		'ftp_nb_fget' 					: [2],
		'ftp_nb_get' 					: [1,2],
		'ftp_nb_put'					: [1],
		'ftp_put'						: [1,2],
		'imap_open'						: [0],
		'imap_mail'						: [0],
		'mail' 							: [0,3],
		'pfsockopen'					: [0],
		'session_register'				: [0],
		'socket_bind'					: [1],
		'socket_connect'				: [1],
		'socket_send'					: [1],
		'socket_write'					: [1],
		'stream_socket_client'			: [0],
		'stream_socket_server'			: [0]
        }

# other critical functions
F_OTHER = {
		'dl' 			 				: [0],
		'ereg'							: [1], # nullbyte injection affected
		'eregi'							: [1], # nullbyte injection affected
		'ini_set' 						: [0,1],
		'ini_restore'					: [0],
		'runkit_constant_redefine'		: [0,1],
		'runkit_method_rename'			: [0,1,2],
		'sleep'							: [0],
		'unserialize'					: [0],
		'extract'						: [0],
		'mb_parse_str'					: [0],
		'parse_str'						: [0],
		'putenv'						: [0],
		'set_include_path'				: [0],
		'apache_setenv'					: [0,1],
		'define'						: [0]
        }

# property oriented programming with unserialize
F_POP = {
		'unserialize'	 		 		: [0],  # calls __destruct
		'is_a'							: [0]   # calls __autoload in php 4.2.7, 4.2.8
        }




A_F_ALL = {
        'Command Execution':F_COMMAND_EXEC,
        'Cross Site Scripting':F_XSS,
        'HTTP Header Injection':F_HTTP_HEADER_INJ,
        'PHP Code Injection': F_CODE_EXEC,
        'Remote/Local File Inclusion':F_FILE_INCLUDE,
        'Arbitrary File Access':F_FILE_READ,
        'SQL Injection':F_DATABASE,
        'XPATH Injection':F_XPATH,
        'LDAP Injection':F_LDAP,
        'Connection Command':F_CONNECT,
        'Other':F_OTHER,
        'POP':F_POP,
        }




##TODO: add methods for frameworks (symphony, yii, ...)
##TODO: add methods for CMS



# default extension loaded in a PHP project
D_EXT_LIST = [
        '.php',
        '.inc',
        '.php5',
        '.php4',
        '.phps',
        '.tpl',
        '.phtml',
        '.cgi'
        ]





###
# Sources
###

# array offset for $_SERVER that are user controlled
V_SERVER_PARAMS = [
        'HTTP_USER_AGENT'  ,
        'HTTP_ACCEPT',
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING',
        'HTTP_ACCET_CHARSET',
        'HTTP_KEEP_ALIVE',
        'HTTP_CONNECTION',
        'HTTP_HOST',
        'QUERY_STRING',
        'REQUEST_URI', #Partially URL encoded
        'PATH_INFO',
        'PATH_TRANSLATED',
        'PHP_SELF'
        ]

# variables considered as user controlled
V_USERINPUT = {
        '$_GET': 'ANY',
        '$_POST': 'ANY',
        '$_COOKIE': 'ANY',
        '$_REQUEST': 'ANY',
        '$_FILES': 'ANY', #Not sur that it is ANY
        '$_SERVER': V_SERVER_PARAMS,
        '$_ENV': 'ANY', #Not for webapplications
        '$HTTP_GET_VARS': 'ANY',
        '$HTTP_POST_VARS': 'ANY',
        '$HTTP_COOKIE_VARS': 'ANY',
        '$HTTP_REQUEST_VARS': 'ANY',
        '$HTTP_POST_FILES': 'ANY',
        '$HTTP_SERVER_VARS': V_SERVER_PARAMS,
        '$HTTP_ENV_VARS': 'ANY', #Not for webapplications
        '$HTTP_RAW_POST_DATA': 'ANY',
        '$argc': 'ANY', #Not for webapplications
        '$argv': 'ANY', #Not for webapplications
        '$_SESSION': 'DEP' #this one needs more analysis, because it is a persistant variable through pages
        }

# user controlled file input
F_FILE_INPUT = [
        'bzread',
        'dio_read',
        'exif_imagetype',
        'exif_read_data',
        'exif_thumbnail',
        'fgets',
        'fgetss',
        'file',
        'file_get_contents',
        'fread',
        'get_meta_tags',
        'glob',
        'gzread',
        'readdir',
        'read_exif_data',
        'scandir',
        'zip_read'
        ]

# user controlled database input, might be intersting for persistent XSS for instance
F_DATABASE_INPUT = [
        'mysql_fetch_array',
        'mysql_fetch_assoc',
        'mysql_fetch_field',
        'mysql_fetch_object',
        'mysql_fetch_row',
        'pg_fetch_all',
        'pg_fetch_array',
        'pg_fetch_assoc',
        'pg_fetch_object',
        'pg_fetch_result',
        'pg_fetch_row',
        'sqlite_fetch_all',
        'sqlite_fetch_array',
        'sqlite_fetch_object',
        'sqlite_fetch_single',
        'sqlite_fetch_string'
        ]

# others !
F_OTHER_INPUT = [
        'get_headers',
        'runkit_superglobals',
        'import_request_variables',
        'getenv',
        'apache_getenv'
        ]


###
# taint parameters
###

T_VARS = [
        phply.phpast.Variable,
        phply.phpast.ArrayOffset
        ]

T_VARS_ARRAY = [
        phply.phpast.ArrayOffset,
        ]

