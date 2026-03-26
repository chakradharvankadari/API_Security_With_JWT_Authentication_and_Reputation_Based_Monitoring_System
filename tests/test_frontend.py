def test_frontend_index_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"Secure API Reputation Console" in res.data
