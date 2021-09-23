package db

import (
	"bytes"
	"fmt"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-kit/kit/metrics/prometheus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	optPkg "github.com/syndtr/goleveldb/leveldb/opt"
)

func init() {
	dbCreator := func(name string, dir string, opt interface{}) (DB, error) {
		if o, ok := opt.(*optPkg.Options); ok {
			return NewGoLevelDBWithOpts(name, dir, o)
		} else {
			return NewGoLevelDB(name, dir)
		}
	}
	registerDBCreator(LevelDBBackend, dbCreator, false)
	registerDBCreator(GoLevelDBBackend, dbCreator, false)
}

var _ DB = (*GoLevelDB)(nil)

type GoLevelDB struct {
	db *leveldb.DB

	closed               bool
	numFilesAtLevelGuage *prometheus.Gauge
	diskSizeGauge        *prometheus.Gauge
	compTimeGauge        *prometheus.Gauge
	compReadGauge        *prometheus.Gauge
	compWriteGauge       *prometheus.Gauge
	writeDelayNGauge     *prometheus.Gauge
	writePauseNGauge     *prometheus.Gauge
	writeDelayGauge      *prometheus.Gauge
	diskReadGauge        *prometheus.Gauge
	diskWriteGauge       *prometheus.Gauge
	memCompGauge         *prometheus.Gauge
	level0CompGauge      *prometheus.Gauge
	nonlevel0CompGauge   *prometheus.Gauge
	seekCompGauge        *prometheus.Gauge
}

func NewGoLevelDB(name string, dir string) (*GoLevelDB, error) {
	return NewGoLevelDBWithOpts(name, dir, nil)
}

func NewGoLevelDBWithOpts(name string, dir string, o *optPkg.Options) (*GoLevelDB, error) {
	dbPath := filepath.Join(dir, name+".db")
	db, err := leveldb.OpenFile(dbPath, o)
	if err != nil {
		return nil, err
	}
	database := &GoLevelDB{
		db: db,
	}
	go database.meter(name, 3*time.Second)
	return database, nil
}

// Implements DB.
func (db *GoLevelDB) Get(key []byte) []byte {
	key = nonNilBytes(key)
	res, err := db.db.Get(key, nil)
	if err != nil {
		if err == errors.ErrNotFound {
			return nil
		}
		panic(err)
	}
	return res
}

// Implements DB.
func (db *GoLevelDB) Has(key []byte) bool {
	return db.Get(key) != nil
}

// Implements DB.
func (db *GoLevelDB) Set(key []byte, value []byte) {
	key = nonNilBytes(key)
	value = nonNilBytes(value)
	err := db.db.Put(key, value, nil)
	if err != nil {
		panic(err)
	}
}

// Implements DB.
func (db *GoLevelDB) SetSync(key []byte, value []byte) {
	key = nonNilBytes(key)
	value = nonNilBytes(value)
	err := db.db.Put(key, value, &optPkg.WriteOptions{Sync: true})
	if err != nil {
		panic(err)
	}
}

// Implements DB.
func (db *GoLevelDB) Delete(key []byte) {
	key = nonNilBytes(key)
	err := db.db.Delete(key, nil)
	if err != nil {
		panic(err)
	}
}

// Implements DB.
func (db *GoLevelDB) DeleteSync(key []byte) {
	key = nonNilBytes(key)
	err := db.db.Delete(key, &optPkg.WriteOptions{Sync: true})
	if err != nil {
		panic(err)
	}
}

func (db *GoLevelDB) DB() *leveldb.DB {
	return db.db
}

// Implements DB.
func (db *GoLevelDB) Close() {
	db.closed = true
	db.db.Close()
}

// Implements DB.
func (db *GoLevelDB) Print() {
	str, _ := db.db.GetProperty("leveldb.stats")
	fmt.Printf("%v\n", str)

	itr := db.db.NewIterator(nil, nil)
	for itr.Next() {
		key := itr.Key()
		value := itr.Value()
		fmt.Printf("[%X]:\t[%X]\n", key, value)
	}
}

// Implements DB.
func (db *GoLevelDB) Stats() map[string]string {
	keys := []string{
		"leveldb.num-files-at-level{n}",
		"leveldb.stats",
		"leveldb.sstables",
		"leveldb.blockpool",
		"leveldb.cachedblock",
		"leveldb.openedtables",
		"leveldb.alivesnaps",
		"leveldb.aliveiters",
	}

	stats := make(map[string]string)
	for _, key := range keys {
		str, err := db.db.GetProperty(key)
		if err == nil {
			stats[key] = str
		}
	}
	return stats
}

var (
	numFilesAtLevelGuage = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "num_files_at_level",
	}, []string{"dbname", "level"})
	diskSizeGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "disk_size",
	}, []string{"dbname", "level"})
	compTimeGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "comp_time",
	}, []string{"dbname", "level"})
	compReadGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "comp_read",
	}, []string{"dbname", "level"})
	compWriteGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "comp_write",
	}, []string{"dbname", "level"})
	writeDelayNGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "write_delay_n",
	}, []string{"dbname"})
	writePauseNGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "write_pause_n",
	}, []string{"dbname"})
	writeDelayGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "write_delay",
	}, []string{"dbname"})
	diskReadGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "disk_read",
	}, []string{"dbname"})
	diskWriteGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "disk_write",
	}, []string{"dbname"})
	memCompGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "mem_comp",
	}, []string{"dbname"})
	level0CompGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "level0_comp",
	}, []string{"dbname"})
	nonlevel0CompGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "nonlevel0_comp",
	}, []string{"dbname"})
	seekCompGauge = prometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "goleveldb",
		Subsystem: "bc",
		Name:      "seek_comp",
	}, []string{"dbname"})
)

func (db *GoLevelDB) meter(name string, refresh time.Duration) {
	var merr error

	timer := time.NewTimer(refresh)
	defer timer.Stop()

	// Iterate ad infinitum and collect the stats
	for i := 1; !db.closed && merr == nil; i++ {
		var stats leveldb.DBStats
		if err := db.db.Stats(&stats); err != nil {
			merr = err
			continue
		}

		for l := range stats.LevelSizes {
			lvl := strconv.Itoa(l)
			numFilesAtLevelGuage.With("dbname", name, "level", lvl).Set(float64(stats.LevelTablesCounts[l]))
			diskSizeGauge.With("dbname", name, "level", lvl).Set(float64(stats.LevelSizes[l]))
			compTimeGauge.With("dbname", name, "level", lvl).Set(float64(stats.LevelDurations[l]))
			compReadGauge.With("dbname", name, "level", lvl).Set(float64(stats.LevelRead[l]))
			compWriteGauge.With("dbname", name, "level", lvl).Set(float64(stats.LevelWrite[l]))
		}

		writeDelayNGauge.With("dbname", name).Set(float64(stats.WriteDelayCount))
		writePauseNGauge.With("dbname", name).Set(float64(stats.WritePauseCount))
		writeDelayGauge.With("dbname", name).Set(float64(stats.WriteDelayDuration))
		diskReadGauge.With("dbname", name).Set(float64(stats.IORead))
		diskWriteGauge.With("dbname", name).Set(float64(stats.IOWrite))

		memCompGauge.With("dbname", name).Set(float64(stats.MemComp))
		level0CompGauge.With("dbname", name).Set(float64(stats.Level0Comp))
		nonlevel0CompGauge.With("dbname", name).Set(float64(stats.NonLevel0Comp))
		seekCompGauge.With("dbname", name).Set(float64(stats.SeekComp))

		// Sleep a bit, then repeat the stats collection
		select {
		case <-timer.C:
			timer.Reset(refresh)
			// Timeout, gather a new set of stats
		}
	}
}

//----------------------------------------
// Batch

// Implements DB.
func (db *GoLevelDB) NewBatch() Batch {
	batch := new(leveldb.Batch)
	return &goLevelDBBatch{db, batch}
}

type goLevelDBBatch struct {
	db    *GoLevelDB
	batch *leveldb.Batch
}

// Implements Batch.
func (mBatch *goLevelDBBatch) Set(key, value []byte) {
	mBatch.batch.Put(key, value)
}

// Implements Batch.
func (mBatch *goLevelDBBatch) Delete(key []byte) {
	mBatch.batch.Delete(key)
}

// Implements Batch.
func (mBatch *goLevelDBBatch) Write() {
	err := mBatch.db.db.Write(mBatch.batch, &optPkg.WriteOptions{Sync: false})
	if err != nil {
		panic(err)
	}
}

// Implements Batch.
func (mBatch *goLevelDBBatch) WriteSync() {
	err := mBatch.db.db.Write(mBatch.batch, &optPkg.WriteOptions{Sync: true})
	if err != nil {
		panic(err)
	}
}

// Implements Batch.
// Close is no-op for goLevelDBBatch.
func (mBatch *goLevelDBBatch) Close() {}

//----------------------------------------
// Iterator
// NOTE This is almost identical to db/c_level_db.Iterator
// Before creating a third version, refactor.

// Implements DB.
func (db *GoLevelDB) Iterator(start, end []byte) Iterator {
	itr := db.db.NewIterator(nil, nil)
	return newGoLevelDBIterator(itr, start, end, false)
}

// Implements DB.
func (db *GoLevelDB) ReverseIterator(start, end []byte) Iterator {
	itr := db.db.NewIterator(nil, nil)
	return newGoLevelDBIterator(itr, start, end, true)
}

type goLevelDBIterator struct {
	source    iterator.Iterator
	start     []byte
	end       []byte
	isReverse bool
	isInvalid bool
}

var _ Iterator = (*goLevelDBIterator)(nil)

func newGoLevelDBIterator(source iterator.Iterator, start, end []byte, isReverse bool) *goLevelDBIterator {
	if isReverse {
		if end == nil {
			source.Last()
		} else {
			valid := source.Seek(end)
			if valid {
				eoakey := source.Key() // end or after key
				if bytes.Compare(end, eoakey) <= 0 {
					source.Prev()
				}
			} else {
				source.Last()
			}
		}
	} else {
		if start == nil {
			source.First()
		} else {
			source.Seek(start)
		}
	}
	return &goLevelDBIterator{
		source:    source,
		start:     start,
		end:       end,
		isReverse: isReverse,
		isInvalid: false,
	}
}

// Implements Iterator.
func (itr *goLevelDBIterator) Domain() ([]byte, []byte) {
	return itr.start, itr.end
}

// Implements Iterator.
func (itr *goLevelDBIterator) Valid() bool {

	// Once invalid, forever invalid.
	if itr.isInvalid {
		return false
	}

	// Panic on DB error.  No way to recover.
	itr.assertNoError()

	// If source is invalid, invalid.
	if !itr.source.Valid() {
		itr.isInvalid = true
		return false
	}

	// If key is end or past it, invalid.
	var start = itr.start
	var end = itr.end
	var key = itr.source.Key()

	if itr.isReverse {
		if start != nil && bytes.Compare(key, start) < 0 {
			itr.isInvalid = true
			return false
		}
	} else {
		if end != nil && bytes.Compare(end, key) <= 0 {
			itr.isInvalid = true
			return false
		}
	}

	// Valid
	return true
}

// Implements Iterator.
func (itr *goLevelDBIterator) Key() []byte {
	// Key returns a copy of the current key.
	// See https://github.com/syndtr/goleveldb/blob/52c212e6c196a1404ea59592d3f1c227c9f034b2/leveldb/iterator/iter.go#L88
	itr.assertNoError()
	itr.assertIsValid()
	return cp(itr.source.Key())
}

// Implements Iterator.
func (itr *goLevelDBIterator) Value() []byte {
	// Value returns a copy of the current value.
	// See https://github.com/syndtr/goleveldb/blob/52c212e6c196a1404ea59592d3f1c227c9f034b2/leveldb/iterator/iter.go#L88
	itr.assertNoError()
	itr.assertIsValid()
	return cp(itr.source.Value())
}

// Implements Iterator.
func (itr *goLevelDBIterator) Next() {
	itr.assertNoError()
	itr.assertIsValid()
	if itr.isReverse {
		itr.source.Prev()
	} else {
		itr.source.Next()
	}
}

// Implements Iterator.
func (itr *goLevelDBIterator) Close() {
	itr.source.Release()
}

func (itr *goLevelDBIterator) assertNoError() {
	if err := itr.source.Error(); err != nil {
		panic(err)
	}
}

func (itr goLevelDBIterator) assertIsValid() {
	if !itr.Valid() {
		panic("goLevelDBIterator is invalid")
	}
}
