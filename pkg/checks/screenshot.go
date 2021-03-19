package checks

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func ImageFromURL(url string) (base64Encoding string) {
	screenshotFile := ScreenshotFromURL(url)
	if screenshotFile == "" {
		log.Printf("Could not fetch screenshot, skipping...")
		return ""
	}
	defer os.Remove(screenshotFile)

	bytes, err := ioutil.ReadFile(screenshotFile)
	if err != nil {
		log.Printf("Could not read file %s: %s", screenshotFile, err)
		return ""
	}

	// Determine the content type of the image file
	mimeType := http.DetectContentType(bytes)

	// Prepend the appropriate URI scheme header depending on the MIME type
	switch mimeType {
	case "image/jpeg":
		base64Encoding += "data:image/jpeg;base64,"
	case "image/png":
		base64Encoding += "data:image/png;base64,"
	}

	// Append the base64 encoded output
	base64Encoding += toBase64(bytes)

	return base64Encoding
}

func ScreenshotFromURL(url string) string {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	tmpFile, err := ioutil.TempFile(os.TempDir(), "saasreconn-scrshot-")
	if err != nil {
		log.Printf("Could not create temporary file")
		return ""
	}

	// Run Screenshot Tasks
	// List of actions to run in sequence (which also fills our image buffer)
	var imageBuf []byte
	if err := chromedp.Run(ctx, screenshotTasks(url, &imageBuf)); err != nil {
		log.Printf("[%s] Error querying page %s", url, err)
		return ""
	}

	// Write our image to file
	if err := ioutil.WriteFile(tmpFile.Name(), imageBuf, 0644); err != nil {
		log.Printf("[%s] Error saving image %s", url, err)
		return ""
	}

	return tmpFile.Name()
}

func screenshotTasks(url string, imageBuf *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.Sleep(time.Second),
		chromedp.ActionFunc(func(ctx context.Context) (err error) {
			*imageBuf, err = page.CaptureScreenshot().WithQuality(90).Do(ctx)
			return err
		}),
	}
}
