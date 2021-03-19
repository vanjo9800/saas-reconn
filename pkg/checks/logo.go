package checks

import (
	"context"
	"log"
	"os"

	vision "cloud.google.com/go/vision/apiv1"
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

	screenshotFile := ScreenshotFromURL(url)
	defer os.Remove(screenshotFile)

	logos, err := detectLogos(screenshotFile)
	if err != nil {
		log.Printf("[%s] Error querying Google Cloud API %s", url, err)
		return logos
	}

	return logos
}
