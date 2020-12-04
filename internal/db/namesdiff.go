package saasreconn

type DataDiff struct {
	added string[]
	removed string[]
}

func (diff *DataDiff) dump() {
	log.Info("Added:\n");
	for _, domain := range diff.added {
		log.Info("\t+ " + domain + "\n");
	}
	log.Info("Removed:\n");
	for _, domain := range diff.removed {
		log.Info("\t- " + domain + "\n");
	}
}
