using System;
using System.IO;

namespace ForensicTool
{
    class Program
    {

        static void Main(string[] args) //sample_1.dd als parameter invoegen
        {
            string filePath = @"C:\Users\elder\Documents\HBO-ICT\jaar 3\Exchange\Modules\Computer Forensics\Sample_1.dd";
            int partitionEntrySize = 16; //for this assignment we will assume that the disk drives are normal MBR's with 16 byte partition entries

            using (FileStream fsSourceDDS = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader binaryReader = new BinaryReader(fsSourceDDS))
            {
                for(int PartitionNumber = 0; PartitionNumber < 4; PartitionNumber++)
                {
                    //byte offset is standaard 0x1BEh = 446d. plus 4 (byte with partition type).
                    fsSourceDDS.Seek(0x1BE + 4 + (PartitionNumber * partitionEntrySize), SeekOrigin.Begin);
                    string PartitionType = binaryReader.ReadByte().ToString("X2"); //in hexadecimal
                    //switch case voor type
                    //if(type != valid) validPartitions -= 1; (validPartitions = 4 variabele aanmaken)

                    fsSourceDDS.Seek(0x1BE + 8 + (PartitionNumber * partitionEntrySize), SeekOrigin.Begin);
                    //lezen van bytes(27-33) kan eventueel in aparte klasse, aangezien dit ook gebruikt wordt bij line37-42
                    byte[] bytes = binaryReader.ReadBytes(4);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(bytes);
                    }
                    string PartitionStartingSectorHexString = BitConverter.ToString(bytes).Replace("-", string.Empty);
                    int PartitionStartingSector = int.Parse(PartitionStartingSectorHexString, System.Globalization.NumberStyles.HexNumber);

                    fsSourceDDS.Seek(0x1BE + 0x0C + (PartitionNumber * partitionEntrySize), SeekOrigin.Begin);
                    bytes = binaryReader.ReadBytes(4);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(bytes);
                    }
                    string PartitionSizeHexString = BitConverter.ToString(bytes).Replace("-", string.Empty);
                    int PartitionSize = int.Parse(PartitionSizeHexString, System.Globalization.NumberStyles.HexNumber);
                    
                    Console.WriteLine("Partition {0}: Type: {1}     Starting Sector: {2}        Size: {3}", PartitionNumber, PartitionType, PartitionStartingSector, PartitionSize);
                    //Console.WriteLine("Total number of valid partitions is: {0}", validPartitions);
                }                
            }
            Console.ReadLine();
        }
    }
}
