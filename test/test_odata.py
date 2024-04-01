import json
from pathlib import Path

import requests

from msgraphhelper import odata

baseurl = "https://api.businesscentral.dynamics.com/v2.0/"

df_dir = Path(__file__).absolute().parent / "datafixtures"


def test_odata_paginator_simple(requests_mock):
    bc = requests.session()

    url = (
        baseurl + "/Company('HH')/Movs_contabilidad?"
        "$filter=startswith(G_L_Account_No, '70') "
        "or startswith(G_L_Account_No, '710') "
        "or startswith(G_L_Account_No, '605') "
        "or startswith(G_L_Account_No, '607') "
        "or startswith(G_L_Account_No, '609') "
        "or startswith(G_L_Account_No, '440') "
        "or G_L_Account_No eq '6210001' "
        "or G_L_Account_No eq '6213000' "
        "or G_L_Account_No eq '6680000' "
        "or G_L_Account_No eq '7681000' "
        "or G_L_Account_No eq '6681000'"
        "&$select=Document_No, Posting_Date"
    )

    first_file = df_dir / "paginator_HH_01.json"
    first_json = json.loads(first_file.read_text())
    requests_mock.get(url, json=first_json)
    resp = bc.get(url)
    paginator = odata.ODataPaginator(resp, bc)
    assert len(tuple(paginator)) == 523


def test_odata_paginator_text():
    bc = requests.session()
    first_file = df_dir / "paginator_HH_01.json"
    first_text = first_file.read_text()
    paginator = odata.ODataPaginator(first_text, bc)
    assert len(tuple(paginator)) == 523


def test_odata_paginator_json():
    bc = requests.session()
    first_file = df_dir / "paginator_HH_01.json"
    first_json = json.loads(first_file.read_text())
    paginator = odata.ODataPaginator(first_json, bc)
    assert len(tuple(paginator)) == 523


def test_odata_paginator_long(requests_mock):
    bc = requests.session()

    firsturl = url = (
        baseurl + "/Company('C1')/Movs_contabilidad?"
        "$filter=startswith(G_L_Account_No, '70') "
        "or startswith(G_L_Account_No, '710') "
        "or startswith(G_L_Account_No, '605') "
        "or startswith(G_L_Account_No, '607') "
        "or startswith(G_L_Account_No, '609') "
        "or startswith(G_L_Account_No, '440') "
        "or G_L_Account_No eq '6210001' "
        "or G_L_Account_No eq '6213000' "
        "or G_L_Account_No eq '6680000' "
        "or G_L_Account_No eq '7681000' "
        "or G_L_Account_No eq '6681000'"
        "&$select=Document_No, Posting_Date"
    )

    for filename in df_dir.glob("paginator_C1_*.json"):
        rj = json.loads(filename.read_text())
        requests_mock.get(url, json=rj)
        if "@odata.nextLink" in rj:
            url = rj["@odata.nextLink"]

    resp = bc.get(firsturl)
    paginator = odata.ODataPaginator(resp, bc)
    assert len(tuple(paginator)) == 63135

    firsturl = url = (
        baseurl + "/Company('HA')/Movs_contabilidad?"
        "$filter=startswith(G_L_Account_No, '70') "
        "or startswith(G_L_Account_No, '710') "
        "or startswith(G_L_Account_No, '605') "
        "or startswith(G_L_Account_No, '607') "
        "or startswith(G_L_Account_No, '609') "
        "or startswith(G_L_Account_No, '440') "
        "or G_L_Account_No eq '6210001' "
        "or G_L_Account_No eq '6213000' "
        "or G_L_Account_No eq '6680000' "
        "or G_L_Account_No eq '7681000' "
        "or G_L_Account_No eq '6681000'"
        "&$select=Document_No, Posting_Date"
    )

    for filename in df_dir.glob("paginator_HA_*.json"):
        rj = json.loads(filename.read_text())
        requests_mock.get(url, json=rj)
        if "@odata.nextLink" in rj:
            url = rj["@odata.nextLink"]

    resp = bc.get(firsturl)
    paginator = odata.ODataPaginator(resp, bc)
    assert len(tuple(paginator)) == 63921
