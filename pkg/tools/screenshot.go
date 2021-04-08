package tools

import (
	"context"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

const screenshotTimeout time.Duration = 20 * time.Second

func Base64ImageFromURL(url string) (base64Encoding string, screenshotError error) {
	imageBytes, err := screenshotFromURLToBytes(url)
	if imageBytes == nil {
		return "", err
	}

	// Determine the content type of the image file
	mimeType := http.DetectContentType(imageBytes)

	// Prepend the appropriate URI scheme header depending on the MIME type
	switch mimeType {
	case "image/jpeg":
		base64Encoding += "data:image/jpeg;base64,"
	case "image/png":
		base64Encoding += "data:image/png;base64,"
	}

	// Append the base64 encoded output
	base64Encoding += ToBase64(imageBytes)

	return base64Encoding, nil
}

func ScreenshotFromURLToFile(url string) (string, error) {
	tmpFile, err := ioutil.TempFile(os.TempDir(), "saasreconn-scrshot-")
	if err != nil {
		log.Printf("Could not create temporary file")
		return "", err
	}

	imageBytes, err := screenshotFromURLToBytes(url)
	if err != nil {
		log.Printf("Could not take screenshot")
		return "", err
	}

	// Write our image to file
	if err := ioutil.WriteFile(tmpFile.Name(), imageBytes, 0644); err != nil {
		log.Printf("[%s] Error saving image %s", url, err)
		return "", err
	}

	return tmpFile.Name(), nil
}

func screenshotFromURLToBytes(url string) (imageBytes []byte, screenshotError error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", "1"),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	timeoutContext, cancel := context.WithTimeout(ctx, screenshotTimeout)
	defer cancel()

	// Run Screenshot Tasks
	if err := chromedp.Run(timeoutContext, screenshotTasks(url, 90, &imageBytes)); err != nil {
		log.Printf("[%s] Error querying page: %s", url, err)
		return nil, err
	}

	return imageBytes, nil
}

func screenshotTasks(url string, quality int64, imageBuffer *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.Sleep(5 * time.Second),
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
