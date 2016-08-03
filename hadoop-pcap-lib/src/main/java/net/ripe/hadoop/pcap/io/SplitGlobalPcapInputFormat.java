package net.ripe.hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.io.reader.PcapRecordReader;
import boundary.RecordBoundaryDetector;
import boundary.RecordFormat;
import boundary.pcap.PcapRecordFormat;

public class SplitGlobalPcapInputFormat extends FileInputFormat<LongWritable, ObjectWritable> {
    static final String READER_CLASS_PROPERTY = "net.ripe.hadoop.pcap.io.reader.class";

    public static final Log LOG = LogFactory.getLog(PcapInputFormat.class);

    @Override
    public RecordReader<LongWritable, ObjectWritable> createRecordReader(InputSplit split, TaskAttemptContext context) throws IOException, InterruptedException {
        FileSplit fileSplit = (FileSplit)split;
        Path path = fileSplit.getPath();
        LOG.info("Reading PCAP: " + path.toString());
        long start = fileSplit.getStart();
        long length = start + fileSplit.getLength() - 1;
        return initPcapRecordReader(path, start, length, context);
    }

    public static PcapRecordReader initPcapRecordReader(Path path, long start, long end, TaskAttemptContext context) throws IOException {
        Configuration conf = context.getConfiguration();
        FileSystem fs = path.getFileSystem(conf);
        FSDataInputStream baseStream = fs.open(path);
        DataInputStream stream = baseStream;
        CompressionCodecFactory compressionCodecs = new CompressionCodecFactory(conf);
        final CompressionCodec codec = compressionCodecs.getCodec(path);

        if (codec != null)
            stream = new DataInputStream(codec.createInputStream(stream));
        
        PcapReader reader = initPcapReader(stream, conf); // reads the first 24 bytes of the file, even remotely

        if (codec == null)
        	baseStream.seek(start);

        return new PcapRecordReader(reader, start, end, baseStream, stream, context);
    }

    public static PcapReader initPcapReader(DataInputStream stream, Configuration conf) {
        try {
            Class<? extends PcapReader> pcapReaderClass = conf.getClass(READER_CLASS_PROPERTY, PcapReader.class, PcapReader.class);
            Constructor<? extends PcapReader> pcapReaderConstructor = pcapReaderClass.getConstructor(DataInputStream.class);
            return pcapReaderConstructor.newInstance(stream);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    protected boolean isSplitable(JobContext context, Path filename) {
		CompressionCodec codec = new CompressionCodecFactory(context.getConfiguration()).getCodec(filename);
		return codec == null;
    }
    
	@Override
	public List<InputSplit> getSplits(JobContext context) throws IOException {
		List<InputSplit> defaultSplits = super.getSplits(context);

		final long startTime = System.currentTimeMillis();

        Configuration conf = context.getConfiguration();
		List<InputSplit> resultSplits = new ArrayList<InputSplit>();

        // We want to do this file by file to avoid opening and reading excessively, so hash the list
        // by path first and then compile the results.  We can throw away unsplittable (compressed)
        // paths and simply not adjust their splits.
        Map<Path, List<FileSplit>> map = new HashMap<Path, List<FileSplit>>();

        for (InputSplit split: defaultSplits) {
        	FileSplit fileSplit = (FileSplit)split;
        	Path path = fileSplit.getPath();

        	if (!map.containsKey(path)) {
        		if (!isSplitable(context, path)) { // if it's not splitable, just add the single split straight to output
        			resultSplits.add(split);
        			continue;
        		}

        		map.put(path, new ArrayList<FileSplit>());
        	}

    		map.get(path).add(fileSplit);
        }

        for (Entry<Path, List<FileSplit>> entry : map.entrySet()) {
        	Path path = entry.getKey();

	        FileSystem fs = path.getFileSystem(conf);
	        FSDataInputStream stream = fs.open(path);
	        PcapReader reader = initPcapReader(stream, conf); // reads the first 24 bytes of the file

        	long snaplen = reader.getSnaplen();
        	boolean reversed = reader.isReverseHeaderByteOrder();
			ByteOrder byteorder = reversed ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
			long fileLen = fs.getFileStatus(path).getLen();
	        
			RecordFormat format = new PcapRecordFormat((int)snaplen, byteorder);
			RecordBoundaryDetector detector = new RecordBoundaryDetector(stream, format);

			// sort the splits by start index, so we can just perform one detection per split.
			List<FileSplit> fileSplits = entry.getValue();
			Collections.sort(fileSplits, new Comparator<FileSplit>() {
				public int compare(FileSplit lhs, FileSplit rhs) {
					return ((Long)lhs.getStart()).compareTo(rhs.getStart());
				}
			});
			
			long last_end = 24;

			// Determine the real start and end if this is splitable
	        for (FileSplit fileSplit : fileSplits) {
        		long end = fileSplit.getStart() + fileSplit.getLength();

        		// In the extremely unlikely event of not finding a solution within a split,
        		// that split will have to be processed by the mapper processing the preceeding split.
        		if (last_end >= end)
        			continue;

        		if (end != fileLen) {
        			stream.seek(end);
        			end += detector.detect();
        		}

        		resultSplits.add(new FileSplit(path, last_end, end - last_end, fileSplit.getLocations()));
        		last_end = end;
			}
		}
		if (false) {
			String outstr = "Took " + (System.currentTimeMillis() - startTime) + " ms.\n";
			for (InputSplit split : resultSplits) {
				FileSplit f = (FileSplit)split;
				outstr += f.getPath() + " " + f.getStart() + " " + f.getLength() + "\n";
			}
			throw new IOException(outstr);
		}
        return resultSplits;
	}
}
