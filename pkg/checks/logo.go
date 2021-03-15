package checks

import (
	"context"
	"io/ioutil"
	"log"
	"os"

	vision "cloud.google.com/go/vision/apiv1"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// detectLogos gets logos from the Vision API for an image at the given file path.
func detectLogos(file string) (logos []string, err error) {
	ctx := context.Background()

	client, err := vision.NewImageAnnotatorClient(ctx)
	if err != nil {
		return logos, err
	}

	f, err := os.Open(file)
	if err != nil {
		return logos, err
	}
	defer f.Close()

	image, err := vision.NewImageFromReader(f)
	if err != nil {
		return logos, err
	}
	annotations, err := client.DetectLogos(ctx, image, nil, 10)
	if err != nil {
		return logos, err
	}

	if len(annotations) == 0 {
		log.Printf("No logos found.\n")
	} else {
		for _, annotation := range annotations {
			logos = append(logos, annotation.Description)
			log.Printf("- %s", annotation.Description)
		}
	}

	return logos, nil
}

func DetectLogosInUrl(url string) (logos []string) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	tmpFile, err := ioutil.TempFile(os.TempDir(), "saasreconn-logo-")
	if err != nil {
		log.Printf("Could not create temporary file")
		return logos
	}
	defer os.Remove(tmpFile.Name())

	// Run Tasks
	// List of actions to run in sequence (which also fills our image buffer)
	var imageBuf []byte
	if err := chromedp.Run(ctx, screenshotTasks(url, &imageBuf)); err != nil {
		log.Printf("[%s] Error querying page %s", url, err)
		return logos
	}

	// Write our image to file
	if err := ioutil.WriteFile(tmpFile.Name(), imageBuf, 0644); err != nil {
		log.Printf("[%s] Error saving image %s", url, err)
		return logos
	}

	logos, err = detectLogos(tmpFile.Name())
	if err != nil {
		log.Printf("[%s] Error querying Google Cloud API %s", url, err)
		return logos
	}

	return logos
}

func screenshotTasks(url string, imageBuf *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) (err error) {
			*imageBuf, err = page.CaptureScreenshot().WithQuality(90).Do(ctx)
			return err
		}),
	}
}
