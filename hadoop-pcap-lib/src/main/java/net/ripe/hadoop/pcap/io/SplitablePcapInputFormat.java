package net.ripe.hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteOrder;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.TaskAttemptContext;

import block.BoundaryDetector;
import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.io.reader.PcapRecordReader;
import pcap.PcapBoundaryDetector;

public class SplitablePcapInputFormat extends PcapInputFormat {
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

        // Determine the real start and end if this is splitable
        if (codec == null) {
        	long snaplen = reader.getSnaplen();
        	boolean reversed = reader.isReverseHeaderByteOrder();

			ByteOrder byteorder = reversed ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
			BoundaryDetector detector = new PcapBoundaryDetector(stream, (int)snaplen, byteorder);

        	if (start == 0) {
        		start = 24L;
        	}
        	else {
            	// determine first unambiguous header index for split
        		baseStream.seek(start);
    			start += detector.detect();
        	}

        	// is this the last split?
        	if (end != path.getFileSystem(conf).getFileStatus(path).getLen()) {
            	// determine first unambiguous header index for NEXT split, remote read until that
        		baseStream.seek(end);
        		end += detector.detect();
        	}
        	
        	stream.close(); // close the stream, open it for real with the PcapRecordReader
        }
        else {
        	start = 24L; // not 0, only effect is on progress though
        }
        
        return new PcapRecordReader(reader, start, end, baseStream, stream, context);
    }

    @Override
    protected boolean isSplitable(JobContext context, Path filename) {
		CompressionCodec codec = new CompressionCodecFactory(context.getConfiguration()).getCodec(filename);
		return codec == null;
    }
}
