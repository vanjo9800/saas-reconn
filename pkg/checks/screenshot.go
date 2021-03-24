package checks

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

const screenshotTimeout time.Duration = 20 * time.Second

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Base64ImageFromURL(url string) string {
	urls := []string{url}
	base64Encodings := Base64ImageFromURLs(urls)

	return base64Encodings[0]
}

func Base64ImageFromURLs(urls []string) (base64Encodings []string) {
	imageBytes := screenshotFromURLToBytes(urls)

	for _, singleImageBytes := range imageBytes {
		// Determine the content type of the image file
		mimeType := http.DetectContentType(singleImageBytes)

		base64Encoding := ""
		// Prepend the appropriate URI scheme header depending on the MIME type
		switch mimeType {
		case "image/jpeg":
			base64Encoding += "data:image/jpeg;base64,"
		case "image/png":
			base64Encoding += "data:image/png;base64,"
		}

		// Append the base64 encoded output
		base64Encoding += toBase64(singleImageBytes)

		base64Encodings = append(base64Encodings, base64Encoding)

	}
	return base64Encodings
}

func ScreenshotFromURLToFile(url string) string {
	tmpFile, err := ioutil.TempFile(os.TempDir(), "saasreconn-scrshot-")
	if err != nil {
		log.Printf("Could not create temporary file")
		return ""
	}

	urls := []string{url}
	imageBytes := screenshotFromURLToBytes(urls)[0]

	// Write our image to file
	if err := ioutil.WriteFile(tmpFile.Name(), imageBytes, 0644); err != nil {
		log.Printf("[%s] Error saving image %s", url, err)
		return ""
	}

	return tmpFile.Name()
}

func screenshotFromURLToBytes(urls []string) (imageBytes [][]byte) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", "1"),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Run Screenshot Tasks
	var screenshotTakers sync.WaitGroup
	for index, url := range urls {
		imageBytes = append(imageBytes, []byte{})
		screenshotTakers.Add(1)
		go func(url string, index int, screenshotTakers *sync.WaitGroup) {
			defer screenshotTakers.Done()
			timeoutContext, cancel := context.WithTimeout(ctx, screenshotTimeout)
			defer cancel()
			if err := chromedp.Run(timeoutContext, screenshotTasks(url, 90, &imageBytes[index])); err != nil {
				log.Printf("[%s] Error querying page: %s", url, err)
			}
		}(url, index, &screenshotTakers)
	}

	screenshotTakers.Wait()
	return imageBytes
}

func screenshotTasks(url string, quality int64, imageBuffer *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.Sleep(3 * time.Second),
		// chromedp.ActionFunc(func(ctx context.Context) (err error) {
		// 	*imageBuf, err = page.CaptureScreenshot().WithQuality(90).Do(ctx)
		// 	return err
		// }),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// get layout metrics
			_, _, contentSize, err := page.GetLayoutMetrics().Do(ctx)
			if err != nil {
				return err
			}

			width, height := int64(math.Ceil(contentSize.Width)), int64(math.Ceil(contentSize.Height))
			height = int64(math.Min(float64(width), float64(height)))

			// force viewport emulation
			err = emulation.SetDeviceMetricsOverride(width, height, 1, false).
				WithScreenOrientation(&emulation.ScreenOrientation{
					Type:  emulation.OrientationTypeLandscapePrimary,
					Angle: 0,
				}).
				Do(ctx)
			if err != nil {
				return err
			}

			// capture screenshot
			*imageBuffer, err = page.CaptureScreenshot().
				WithQuality(quality).
				WithClip(&page.Viewport{
					X:      contentSize.X,
					Y:      contentSize.Y,
					Width:  contentSize.Width,
					Height: math.Min(contentSize.Width, contentSize.Height),
					Scale:  1,
				}).Do(ctx)
			if err != nil {
				return err
			}
			return nil
		}),
	}
}
