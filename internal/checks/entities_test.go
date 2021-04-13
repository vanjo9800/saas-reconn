package checks

import "testing"

func TestSubdomainBase(t *testing.T) {
	var base SubdomainBase = "example.com"
	expectedBase := "example.com"
	expectedUrl := "http://test.example.com"

	resultBase := base.GetBase()
	if resultBase != expectedBase {
		t.Errorf("[SubdomainBase.GetBase()] got %s, expected %s", resultBase, expectedBase)
	}

	resultUrl := base.GetUrl("test")
	if resultUrl != expectedUrl {
		t.Errorf("[SubdomainBase.GetUrl(test)] got %s, expected %s", resultUrl, expectedUrl)
	}
}

func TestSubdirectoryBase(t *testing.T) {
	var base SubdirectoryBase = "example.com/"
	expectedBase := "example.com/"
	expectedUrl := "http://example.com/test"

	resultBase := base.GetBase()
	if resultBase != expectedBase {
		t.Errorf("[SubdomainBase.GetBase()] got %s, expected %s", resultBase, expectedBase)
	}

	resultUrl := base.GetUrl("test")
	if resultUrl != expectedUrl {
		t.Errorf("[SubdomainBase.GetUrl(test)] got %s, expected %s", resultUrl, expectedUrl)
	}
}
