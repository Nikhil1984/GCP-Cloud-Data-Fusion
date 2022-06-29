class ZCL_GCP_API_HANDLER definition
  public
  final
  create public .

public section.

  class-methods CREATE_SIGNED_JWT
    importing
      !IV_JWT_HEADER type ZGCP_JWT_HEADER
      !IV_JWT_PAYLOAD type ZGCP_JWT_PAYLOAD
      !IV_SSF_PROFILENAME type STRING
      !IV_SSF_ID type STRING
      !IV_SSF_RESULT type I
    returning
      value(RV_SIGNED_JWT_BASE64) type STRING
    raising
      CX_ABAP_PSE .
  class-methods EXCHANGE_JWT_TOKEN
    importing
      !IV_DESTINATION type C
      !IV_JWT_TOKEN type STRING
    returning
      value(RV_ACCESS_TOK) type STRING
    raising
      CX_ABAP_PSE .
  class-methods DO_API_REQUEST
    importing
      !IV_DESTINATION type C
      !IV_OIDC_TOKEN type STRING
      !IV_METHOD type STRING
      !IV_XCONTENT type XSTRING optional
      !IV_CONTENT type STRING optional
      !IV_SUB_URI type STRING optional
      !IT_HEADER_FIELDS type TIHTTPNVP optional
      !IT_COOKIES type TIHTTPCKI optional
      !IV_CONTENT_TYPE type STRING default 'application/json'
    returning
      value(RS_RESPONSE) type STRING
    raising
      CX_ABAP_PSE .
  class-methods GET_IAT_UNIXTIME
    returning
      value(RV_IAT) type INT4 .
protected section.
PRIVATE SECTION.

  TYPES:
    ltty_tssfbin TYPE STANDARD TABLE OF ssfbin WITH KEY table_line WITHOUT FURTHER SECONDARY KEYS .
  TYPES:
    BEGIN OF oidc_token_json,
      access_token TYPE string,
    END OF oidc_token_json .

  CLASS-METHODS string_to_binary_tab
    IMPORTING
      !iv_string        TYPE string
    RETURNING
      VALUE(rt_bin_tab) TYPE ltty_tssfbin
    RAISING
      cx_abap_pse .
  CLASS-METHODS binary_tab_to_string
    IMPORTING
      !it_bin_tab      TYPE ltty_tssfbin
      !iv_length       TYPE ssflen
    RETURNING
      VALUE(rv_string) TYPE string
    RAISING
      cx_abap_pse .
  CLASS-METHODS base64_url_encode
    CHANGING
      !iv_base64 TYPE string .
ENDCLASS.



CLASS ZCL_GCP_API_HANDLER IMPLEMENTATION.


  METHOD base64_url_encode.
    REPLACE ALL OCCURRENCES OF '=' IN iv_base64 WITH ''.
    REPLACE ALL OCCURRENCES OF '+' IN iv_base64 WITH '-'.
    REPLACE ALL OCCURRENCES OF '/' IN iv_base64 WITH '_'.
  ENDMETHOD.


  METHOD binary_tab_to_string.
    CALL FUNCTION 'SCMS_BINARY_TO_STRING'
      EXPORTING
        input_length = iv_length
        encoding     = '4110'
      IMPORTING
        text_buffer  = rv_string
      TABLES
        binary_tab   = it_bin_tab
      EXCEPTIONS
        failed       = 1
        OTHERS       = 2.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE cx_abap_pse.
*        EXPORTING
*          textid = zcx_gcp_api_handler=>zcx_bintostr_conversion_failed.
    ENDIF.
  ENDMETHOD.


  METHOD create_signed_jwt.
    DATA lt_input_bin  TYPE STANDARD TABLE OF ssfbin.
    DATA lt_output_bin TYPE STANDARD TABLE OF ssfbin.
    DATA lv_input_length TYPE ssflen.
    DATA lv_output_length TYPE ssflen.
    DATA lv_output_crc TYPE ssfreturn.
    DATA lt_signer     TYPE STANDARD TABLE OF ssfinfo.
    DATA lv_unix_iat   TYPE string.

    DATA(lv_jwt_payload) = /ui2/cl_json=>serialize(
         data  = iv_jwt_payload
         pretty_name = /ui2/cl_json=>pretty_mode-low_case ).

    DATA(lv_jwt_header) = /ui2/cl_json=>serialize(
           data  = iv_jwt_header
           pretty_name = /ui2/cl_json=>pretty_mode-low_case ).

    DATA(lv_jwt_header_base64)  = cl_http_utility=>encode_base64( unencoded = lv_jwt_header ).
    DATA(lv_jwt_payload_base64) = cl_http_utility=>encode_base64( unencoded = lv_jwt_payload ).

    DATA(lv_data_base64) = |{ lv_jwt_header_base64 }.{ lv_jwt_payload_base64 }|.
    base64_url_encode(
      CHANGING
        iv_base64 = lv_data_base64 ).

    TRY.
        lt_input_bin = string_to_binary_tab( iv_string = lv_data_base64 ).
      CATCH cx_abap_pse INTO DATA(lo_cx).
        RAISE EXCEPTION TYPE cx_abap_pse.
*          EXPORTING
*            textid = CONV #( lo_cx->textid ).
    ENDTRY.

    lt_signer = VALUE #( ( id = iv_ssf_id profile = iv_ssf_profilename result = iv_ssf_result ) ).

    lv_input_length = strlen( lv_data_base64 ).

    CALL FUNCTION 'SSF_KRN_SIGN'
      EXPORTING
        str_format                   = 'PKCS1-V1.5'
        b_inc_certs                  = abap_false
        b_detached                   = abap_false
        b_inenc                      = abap_false
        ostr_input_data_l            = lv_input_length
        str_hashalg                  = 'SHA256'
      IMPORTING
        ostr_signed_data_l           = lv_output_length
        crc                          = lv_output_crc    " SSF Return code
      TABLES
        ostr_input_data              = lt_input_bin
        signer                       = lt_signer
        ostr_signed_data             = lt_output_bin
      EXCEPTIONS
        ssf_krn_error                = 1
        ssf_krn_noop                 = 2
        ssf_krn_nomemory             = 3
        ssf_krn_opinv                = 4
        ssf_krn_nossflib             = 5
        ssf_krn_signer_list_error    = 6
        ssf_krn_input_data_error     = 7
        ssf_krn_invalid_par          = 8
        ssf_krn_invalid_parlen       = 9
        ssf_fb_input_parameter_error = 10.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE cx_abap_pse.
*        EXPORTING
*          textid = cx_abap_pse=>zcx_signature_failed.
    ENDIF.

    TRY.
        DATA(lv_signature) = binary_tab_to_string( it_bin_tab = lt_output_bin
                                                   iv_length  = lv_output_length ).
      CATCH cx_abap_pse INTO DATA(lo_zcx).
        RAISE EXCEPTION TYPE cx_abap_pse.
*          EXPORTING
*            textid = lo_zcx->textid.
    ENDTRY.

    DATA(lv_jwt) = |{ lv_data_base64 }.{ cl_http_utility=>encode_base64( unencoded = lv_signature ) }|.

    base64_url_encode(
      CHANGING
        iv_base64 = lv_jwt  ).

    rv_signed_jwt_base64 = lv_jwt.
  ENDMETHOD.


  METHOD do_api_request.
    DATA lo_client_api TYPE REF TO if_http_client.
    DATA lv_response   TYPE string.
    DATA lv_oidc       TYPE string.

    CALL METHOD cl_http_client=>create_by_destination
      EXPORTING
        destination              = iv_destination
      IMPORTING
        client                   = lo_client_api
      EXCEPTIONS
        argument_not_found       = 1
        destination_not_found    = 2
        destination_no_authority = 3
        plugin_not_active        = 4
        internal_error           = 5
        OTHERS                   = 6.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE cx_abap_pse.
*        EXPORTING
*          textid = cx_abap_pse=>zcx_api_dest_not_found.
    ENDIF.

    IF lo_client_api IS BOUND.
      lv_oidc = |Bearer { iv_oidc_token }|.

      lo_client_api->request->set_header_fields( fields = it_header_fields ).

      lo_client_api->request->set_content_type( content_type = iv_content_type ).
      lo_client_api->request->set_method( method = iv_method ).

*         set jwt token auth
      lo_client_api->request->set_header_field(
          name  = 'Authorization' ##NO_TEXT
          value = lv_oidc
      ).
      lo_client_api->request->set_header_field(
          name  = 'content-type'
          value = iv_content_type
      ).


      IF iv_sub_uri IS NOT INITIAL.
        cl_http_utility=>set_request_uri(
            request = lo_client_api->request
            uri     = iv_sub_uri
        ).
      ENDIF.

      IF iv_xcontent IS NOT INITIAL.
        lo_client_api->request->set_data( data = iv_xcontent ).
      ENDIF.

      IF iv_content IS NOT INITIAL.
        lo_client_api->request->set_cdata( data = iv_content ).
      ENDIF.

      LOOP AT it_cookies ASSIGNING FIELD-SYMBOL(<cookie>).
        lo_client_api->request->set_cookie(
          EXPORTING
            name    = <cookie>-name                 " Name of cookie
            path    = <cookie>-path               " Path of Cookie
            value   = <cookie>-value                 " Cookie value
            domain  = <cookie>-xdomain               " Domain Name of Cookie
            expires = <cookie>-expires               " Cookie expiry date
            secure  = <cookie>-secure                " 0: unsaved; 1:saved
        ).
      ENDLOOP.

      lo_client_api->send( ).
      lo_client_api->receive(
        EXCEPTIONS
          http_communication_failure = 1
          http_invalid_state         = 2
          http_processing_failed     = 3
      ).
      IF sy-subrc <> 0.
        RAISE EXCEPTION TYPE cx_abap_pse.
*          EXPORTING
*            textid = cx_abap_pse=>zcx_api_receive_failed.
      ENDIF.

      rs_response = lo_client_api->response->get_data( ).
      lo_client_api->response->get_status( IMPORTING code   = DATA(lv_code)
                                                     reason = DATA(lv_reason) ).

      CONCATENATE rs_response lv_reason INTO rs_response SEPARATED BY space.
*      lo_client_api->response->get_cookies( CHANGING cookies = rs_response-cookies ).
    ENDIF.
  ENDMETHOD.


  METHOD EXCHANGE_JWT_TOKEN.
    DATA lo_client  TYPE REF TO if_http_client.
    DATA ls_response TYPE oidc_token_json.

    CALL METHOD cl_http_client=>create_by_destination
      EXPORTING
        destination              = iv_destination
      IMPORTING
        client                   = lo_client
      EXCEPTIONS
        argument_not_found       = 1
        destination_not_found    = 2
        destination_no_authority = 3
        plugin_not_active        = 4
        internal_error           = 5
        OTHERS                   = 6.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE cx_abap_pse.
*        EXPORTING
*          textid = cx_abap_pse=>zcx_oauth_dest_not_found.
    ENDIF.

    IF lo_client IS BOUND.
      lo_client->request->set_header_field( name  = 'content-type'
                                            value = 'application/x-www-form-urlencoded' ).
      lo_client->request->set_method( if_http_request=>co_request_method_post ).
*      lo_client->request->set_formfield_encoding( formfield_encoding = if_http_entity=>co_formfield_encoding_encoded ).

      lo_client->request->set_form_field(
        EXPORTING
          name  = 'grant_type'
          value = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
      ).

      lo_client->request->set_form_field(
        EXPORTING
          name  = 'assertion'
          value = iv_jwt_token
      ).

      lo_client->send( ).
      lo_client->receive(
        EXCEPTIONS
          http_communication_failure = 1
          http_invalid_state         = 2
          http_processing_failed     = 3
      ).
      IF sy-subrc <> 0.
        RAISE EXCEPTION TYPE cx_abap_pse.
*          EXPORTING
*            textid = cx_abap_pse=>zcx_oauth_token_receive_fail.
      ENDIF.

      DATA(lv_response_json) = lo_client->response->get_cdata( ).

      /ui2/cl_json=>deserialize(
        EXPORTING
          json = lv_response_json
          pretty_name = /ui2/cl_json=>pretty_mode-camel_case
        CHANGING data = ls_response ).

      IF ls_response-access_token IS INITIAL.
        RAISE EXCEPTION TYPE cx_abap_pse.
*          EXPORTING
*            textid = cx_abap_pse=>zcx_oauth_token_receive_fail.
      ENDIF.
      rv_access_tok = ls_response-access_token.
    ENDIF.
  ENDMETHOD.


  METHOD get_iat_unixtime.
    DATA lv_unix_iat TYPE string.

    GET TIME STAMP FIELD DATA(lv_timestamp).

    CONVERT TIME STAMP lv_timestamp TIME ZONE 'UTC' INTO DATE DATA(lv_date) TIME DATA(lv_time).

    cl_pco_utility=>convert_abap_timestamp_to_java(
      EXPORTING
        iv_date      = lv_date
        iv_time      = lv_time
        iv_msec      = 0
      IMPORTING
        ev_timestamp = lv_unix_iat
    ).

    rv_iat = substring( val = lv_unix_iat off = 0 len = strlen( lv_unix_iat ) - 3 ).
  ENDMETHOD.


  METHOD string_to_binary_tab.
    DATA lv_xstring TYPE xstring.
    CALL FUNCTION 'SCMS_STRING_TO_XSTRING'
      EXPORTING
        text     = iv_string
        encoding = '4110'
      IMPORTING
        buffer   = lv_xstring
      EXCEPTIONS
        failed   = 1
        OTHERS   = 2.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE CX_ABAP_PSE.
*        EXPORTING
*          textid = CX_ABAP_PSE=>zcx_strtobin_conversion_failed.
    ENDIF.

    CALL FUNCTION 'SCMS_XSTRING_TO_BINARY'
      EXPORTING
        buffer     = lv_xstring
      TABLES
        binary_tab = rt_bin_tab.
  ENDMETHOD.
ENDCLASS.
