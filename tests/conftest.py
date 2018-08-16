import pytest

TEST_API_KEY = ''
TEST_MERCHANT = '999666'


def pytest_addoption(parser):
    parser.addoption('--api-key', action='store', type=str,  required=True, default=TEST_API_KEY)
    parser.addoption('--merchant-id', action='store', type=int, default=TEST_MERCHANT)


@pytest.fixture(scope='class')
def api_key(request):
    request.cls.api_key = request.config.getoption('--api-key')


@pytest.fixture(scope='class')
def merchant_id(request):
    request.cls.merchant_id = request.config.getoption('--merchant-id')
