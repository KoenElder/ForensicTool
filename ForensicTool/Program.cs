using System;
using System.IO;

namespace ForensicTool
{
    class Program
    {

        static void Main(string[] args) //sample_1.dd als parameter invoegen
        {
            if(args.Length == 0)
            {
                Console.WriteLine("This Application Needs A File As A Parameter.");
                Console.WriteLine("Please Execute The Program Again From Command Line With The A Parameter.");
                Console.ReadLine();
                Environment.Exit(0);
            }
            string filePath = args[0];//@"C:\Users\elder\Documents\HBO-ICT\jaar 3\Exchange\Modules\Computer Forensics\Sample_1.dd";
            int partitionEntrySize = 16; //for this assignment we will assume that the disk drives are normal MBR's with 16 byte partition entries
            int validPartitions = 4; //standard MBR has 4 partitions
            File File = new File(filePath);

            for(int PartitionNumber = 0; PartitionNumber < 4; PartitionNumber++)
            {
                ////byte offset is standaard 0x1BEh = 446d. plus 4 (byte with partition type).
                string PartitionType = File.GetValueFromBytes((0x1BE + 4 + (PartitionNumber * partitionEntrySize)), 1);
                PartitionType = GetDescriptionFromPartitionType(PartitionType);
                if (PartitionType == "Not-Valid") validPartitions -= 1;

                string PartitionStartingSector = File.GetValueFromBytes((0x1BE + 8 + (PartitionNumber * partitionEntrySize)), 4);

                string PartitionSize = File.GetValueFromBytes((0x1BE + 0x0C + (PartitionNumber * partitionEntrySize)), 4);

                Console.WriteLine("Partition {0}: Type: {1}     Starting Sector: {2}        Size: {3}", PartitionNumber, PartitionType, PartitionStartingSector, PartitionSize);
            }
            Console.WriteLine(); //empty line for readability
            Console.WriteLine("Total number of valid partitions is: {0}", validPartitions);
            Console.ReadLine();
        }

        static private string GetDescriptionFromPartitionType(string PartitionType)
        {
            switch (PartitionType)
            {
                case "00":
                    return "Not-Valid";
                case "01":
                    return "12-bit FAT";
                case "02":
                    return "XENIX root";
                case "03":
                    return "XENIX usr";
                case "04":
                    return "16-bit FAT (<32MB)";
                case "05":
                    return "Extended MS-DOS Partition";
                case "06":
                    return "FAT-16 (32MB to 2GB)";
                case "07":
                    return "NTFS";
                case "08":
                    return "Logical sectored FAT12 or FAT-16, OS/2, AIX boot/split";
                case "09":
                    return "AIX data/boot";
                case "0B":
                    return "FAT-32 (CHS)";
                case "0C":
                    return "FAT-32 (LBA)";
                case "0E":
                    return "FAT-16 (LBA)";
                case "83":
                    return "Any native Linux file system";
                case "93":
                    return "Hidden Linux file system";
                case "A8":
                    return "Apple Darwin, Mac OS X UFS";
                case "AF":
                    return "HFS and HFS+";
                default:
                    return "Not Supported In This Forensic Tool";
            }
        }
    }

    class File
    {
        public File(string filePath)
        {
            FilePath = filePath;
        }
        
        static private string _filePath;
        public string FilePath
        {
            get { return _filePath; }
            set { _filePath = value; }
        }

        static public string GetValueFromBytes(long byteOffset, int byteLength)
        {
            using (FileStream fsSourceDDS = new FileStream(_filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader binaryReader = new BinaryReader(fsSourceDDS))
            {
                fsSourceDDS.Seek(byteOffset, SeekOrigin.Begin);

                if(byteLength == 1)
                {
                    string PartitionType = binaryReader.ReadByte().ToString("X2");
                    return PartitionType;
                }
                else
                {
                    byte[] bytes = binaryReader.ReadBytes(byteLength);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(bytes);
                    }
                    string PartitionStartingSectorHexString = BitConverter.ToString(bytes).Replace("-", string.Empty);

                    int DecimalValue = int.Parse(PartitionStartingSectorHexString, System.Globalization.NumberStyles.HexNumber);
                    return DecimalValue.ToString();
                }                
            }
        }
    }
}
