from msgraphhelper import url


def test_baseurl_development(monkeypatch):
    monkeypatch.setenv("AZURE_FUNCTIONS_ENVIRONMENT", "Development")
    monkeypatch.setenv("WEBSITE_HOSTNAME", "localhost:7073")

    baseurl = url.get_baseurl()
    assert baseurl == "http://localhost:7073/api"


def test_baseurl_production(monkeypatch):
    monkeypatch.setenv("AZURE_FUNCTIONS_ENVIRONMENT", "Production")
    monkeypatch.setenv("WEBSITE_HOSTNAME", "example-function.azurewebsites.net")

    baseurl = url.get_baseurl()
    assert baseurl == "https://example-function.azurewebsites.net/api"


def test_baseurl_development_hosts(monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_FUNCTIONS_ENVIRONMENT", "Development")
    monkeypatch.setenv("WEBSITE_HOSTNAME", "localhost:7073")

    hostconfig = tmp_path / "hosts.json"
    hostconfig.write_text('{"extensions": {"http": {"routePrefix": "myapi"}}}')

    baseurl = url.get_baseurl(host_path=hostconfig)
    assert baseurl == "http://localhost:7073/myapi"


def test_baseurl_development_local_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_FUNCTIONS_ENVIRONMENT", "Development")
    monkeypatch.delenv("WEBSITE_HOSTNAME", raising=False)

    local_settings = tmp_path / "local.settings.json"
    local_settings.write_text('{"Host": {"LocalHttpPort": 7074}}')

    baseurl = url.get_baseurl(local_settings_path=local_settings)
    assert baseurl == "http://localhost:7074/api"
