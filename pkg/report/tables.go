package report

// func DrawTable(report pdf.Maroto, header []string, contents []SubdomainRow, prop ...props.TableList) {
// 	if len(header) == 0 || len(contents) == 0 {
// 		return
// 	}

// 	tableProp := props.TableList{}
// 	if len(prop) > 0 {
// 		tableProp = prop[0]
// 	}
// 	tableProp.MakeValid(header, consts.Arial)

// 	headerHeight := calcLinesHeight(header, tableProp.HeaderProp, tableProp.Align)

// 	report.Row(headerHeight+1, func() {
// 		for i, h := range header {
// 			hs := h

// 			report.Col(tableProp.HeaderProp.GridSizes[i], func() {
// 				reason := hs
// 				report.Text(reason, tableProp.HeaderProp.ToTextProp(tableProp.Align, 0, false, 0.0))
// 			})
// 		}
// 	})

// 	report.Row(tableProp.HeaderContentSpace, func() {
// 		report.ColSpace(0)
// 	})

// 	for index, content := range contents {
// 		contentHeight := calcLinesHeight(report, content, tableProp.ContentProp, tableProp.Align)

// 		if tableProp.AlternatedBackground != nil && index%2 == 0 {
// 			report.SetBackgroundColor(*tableProp.AlternatedBackground)
// 		}

// 		report.Row(contentHeight+1, func() {
// 			for i, c := range content {
// 				cs := c

// 				report.Col(tableProp.ContentProp.GridSizes[i], func() {
// 					report.Text(cs, tableProp.ContentProp.ToTextProp(tableProp.Align, 0, false, 0.0))
// 				})
// 			}
// 		})

// 		if tableProp.AlternatedBackground != nil && index%2 == 0 {
// 			report.SetBackgroundColor(color.NewWhite())
// 		}

// 		if tableProp.Line {
// 			report.Line(1.0)
// 		}
// 	}

// 	report.Row(15, func() {
// 		report.ColSpace(12)
// 	})
// }

// // Will probably need to customize
// func calcLinesHeight(report pdf.Maroto, textList []string, contentProp props.TableListContent, align consts.Align) float64 {
// 	maxLines := 1.0

// 	left, _, right, _ := report.GetPageMargins()
// 	width, _ := report.GetPageSize()
// 	usefulWidth := float64(width - left - right)

// 	textProp := contentProp.ToTextProp(align, 0, false, 0.0)

// 	reportPdf := report.(*pdf.PdfMaroto)
// 	for i, text := range textList {
// 		gridSize := float64(contentProp.GridSizes[i])
// 		percentSize := gridSize / consts.MaxGridSum
// 		colWidth := usefulWidth * percentSize
// 		qtdLines := float64(reportPdf.TextHelper.GetLinesQuantity(text, textProp, colWidth))
// 		if qtdLines > maxLines {
// 			maxLines = qtdLines
// 		}
// 	}

// 	// Font size corrected by the scale factor from "mm" inside gofpdf f.k
// 	fontHeight := reportPdf.Font.GetSize() / reportPdf.Font.GetScaleFactor()

// 	return fontHeight * maxLines
// }
