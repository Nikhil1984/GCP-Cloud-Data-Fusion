*&---------------------------------------------------------------------*
*& Report ZBP_CDS_REP_BQUERY
*&---------------------------------------------------------------------*
*&
*&---------------------------------------------------------------------*
REPORT zbp_cds_rep_bquery.
DATA: lv_url         TYPE string,
      lv_auth        TYPE string,
      lo_client      TYPE REF TO if_http_client,
      lo_rest        TYPE REF TO cl_rest_http_client,
      lv_data        TYPE string,
      lv_return_code TYPE i.

TYPES: BEGIN OF ty_var,
         bp_num TYPE string,
       END OF ty_var.

DATA: lv_var TYPE ty_var.

PARAMETERS: p_bp   TYPE bu_partner.


DATA(lv_iat) = zcl_gcp_api_handler=>get_iat_unixtime( ).
DATA(ls_jwt_payload) = VALUE zgcp_jwt_payload( iss   = 'cortex-dataproc@bionic-charge-290419.iam.gserviceaccount.com'
                                               scope = 'https://www.googleapis.com/auth/cloud-platform'
                                               aud   = 'https://oauth2.googleapis.com/token'
                                               iat   = lv_iat
                                               exp   = lv_iat + 30 ).

DATA(ls_jwt_header) = VALUE zgcp_jwt_header( typ = 'JWT'
                                             alg = 'RS256' ).

TRY.
    DATA(lv_signed_jwt) = zcl_gcp_api_handler=>create_signed_jwt(
      EXPORTING
        iv_jwt_header        = ls_jwt_header
        iv_jwt_payload       = ls_jwt_payload
        iv_ssf_profilename   = 'SAPJWT_SI100.pse'
        iv_ssf_id            = '<implicit>'
        iv_ssf_result        = 28
    ).
  CATCH cx_root.
ENDTRY.

TRY.
    DATA(lv_token) = zcl_gcp_api_handler=>exchange_jwt_token(
                    iv_destination = 'GCP_OAUTH2_TOKEN'
                    iv_jwt_token   = lv_signed_jwt
    ).
  CATCH cx_root.
ENDTRY.


lv_url = 'https://s4-bq-bionic-charge-290419-dot-use4.datafusion.googleusercontent.com/api/v3/namespaces/default/apps/BP_CDS_DELTA/preferences'.

CONCATENATE 'Bearer' lv_token INTO lv_auth SEPARATED BY space.

TRY.
    CALL METHOD cl_http_client=>create_by_url
      EXPORTING
        url                = lv_url
      IMPORTING
        client             = lo_client
      EXCEPTIONS
        argument_not_found = 1
        plugin_not_active  = 2
        internal_error     = 3.
    IF sy-subrc = 0.
      " Set header fields.
      lo_client->request->set_method('GET').
      lo_client->request->set_header_field( name = 'Authorization' value = lv_auth ).
      lo_client->propertytype_logon_popup = lo_client->co_disabled.
      "send and receive
      lo_client->send( ).
      lo_client->receive( ).

      "get status
      lo_client->response->get_status( IMPORTING code = lv_return_code ).
*      "get the response
      lv_data = lo_client->response->get_cdata( ).
*      "close connection
      lo_client->close( ).

      lv_url = 'https://s4-bq-bionic-charge-290419-dot-use4.datafusion.googleusercontent.com/api/v3/namespaces/default/apps/BP_CDS_DELTA/preferences'.

      TRY.
          CALL METHOD cl_http_client=>create_by_url
            EXPORTING
              url                = lv_url
            IMPORTING
              client             = lo_client
            EXCEPTIONS
              argument_not_found = 1
              plugin_not_active  = 2
              internal_error     = 3.
          IF sy-subrc = 0.
            " Set header fields.
            CONCATENATE '''' p_bp '''' INTO lv_var-bp_num.
            DATA(lv_json) = /ui2/cl_json=>serialize( data        = lv_var
                                                     pretty_name = /ui2/cl_json=>pretty_mode-camel_case
                                                     compress    = abap_true ).

            lo_client->request->set_method('PUT').
            lo_client->request->set_header_field( name = 'Authorization' value = lv_auth ).

            CREATE OBJECT lo_rest
              EXPORTING
                io_http_client = lo_client.

            DATA(lo_request) = lo_rest->if_rest_client~create_request_entity( ).
            lo_request->set_content_type( iv_media_type = if_rest_media_type=>gc_appl_json ).
            lo_request->set_content_compression( abap_true ).
            lo_request->set_string_data( lv_json ).

            "send and receive
            lo_client->send( ).
            lo_client->receive( ).

            "get status
            lo_client->response->get_status( IMPORTING code = lv_return_code ).

*      "get the response as binary data
*      lv_data = lo_client->response->get_data( ).
*
*      "close connection
            lo_client->close( ).
          ENDIF.
        CATCH cx_root INTO DATA(lo_root).
      ENDTRY.
    ENDIF. "sy-subrc = 0

    TRY.

        lv_url = 'https://s4-bq-bionic-charge-290419-dot-use4.datafusion.googleusercontent.com/api/v3/namespaces/default/apps/BP_CDS_DELTA/workflows/DataPipelineWorkflow/start'.

        CALL METHOD cl_http_client=>create_by_url
          EXPORTING
            url                = lv_url
          IMPORTING
            client             = lo_client
          EXCEPTIONS
            argument_not_found = 1
            plugin_not_active  = 2
            internal_error     = 3.
        IF sy-subrc = 0.
          " Set header fields.

          lo_client->request->set_method('POST').
          lo_client->request->set_header_field( name = 'Authorization' value = lv_auth ).

          "send and receive
          lo_client->send( ).
          lo_client->receive( ).

          "get status
          lo_client->response->get_status( IMPORTING code = lv_return_code ).

*      "get the response as binary data
*      lv_data = lo_client->response->get_data( ).
*
*      "close connection
          lo_client->close( ).
        ENDIF.
      CATCH cx_root INTO lo_root.
    ENDTRY.
  CATCH cx_root INTO lo_root.
ENDTRY.
