package net.ripe.hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.ByteOrder;

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

public class SplitLocalPcapInputFormat extends FileInputFormat<LongWritable, ObjectWritable> {
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

//        long orig_start = start, orig_end = end;
        
        PcapReader reader = initPcapReader(stream, conf); // reads the first 24 bytes of the file, even remotely

        // Determine the real start and end if this is splitable
        if (codec == null) {
        	long snaplen = reader.getSnaplen();
        	boolean reversed = reader.isReverseHeaderByteOrder();

			ByteOrder byteorder = reversed ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
			
			RecordFormat format = new PcapRecordFormat((int)snaplen, byteorder);
			RecordBoundaryDetector detector = new RecordBoundaryDetector(stream, format);

        	if (start == 0) {
        		start = 24L;
        	}
        	else {
            	// determine first unambiguous header index for split
        		baseStream.seek(start);
    			start += detector.detect();
        	}

        	// is this the last split?
        	if (end != path.getFileSystem(conf).getFileStatus(path).getLen() - 1) {
            	// determine first unambiguous header index for NEXT split, remote read until that
        		baseStream.seek(end);
        		end += detector.detect() - 1;
        	}
        }
        else {
        	start = 24L; // not 0, only effect is on progress though
        }

//        if (true)
//        throw new IOException("from IS start " + orig_start + ", end " + orig_end + ", determined start " + start + ", end " + end);
        
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
}
