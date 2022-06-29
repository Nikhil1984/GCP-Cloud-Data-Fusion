FUNCTION zfm_trigger_bigquery.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(OBJTYPE) TYPE  SWETYPECOU-OBJTYPE
*"     VALUE(OBJKEY) TYPE  SWEINSTCOU-OBJKEY
*"     VALUE(EVENT) TYPE  SWEINSTCOU-EVENT
*"     VALUE(RECTYPE) TYPE  SWETYPECOU-RECTYPE
*"  TABLES
*"      EVENT_CONTAINER STRUCTURE  SWCONT
*"----------------------------------------------------------------------
  DATA: lv_bp TYPE but000-partner.

  lv_bp = CONV #( objkey ).
  SUBMIT zbp_cds_rep_bquery WITH p_bp = lv_bp and RETURN.

ENDFUNCTION.
