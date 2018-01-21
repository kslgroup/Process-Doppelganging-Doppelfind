# Author: KSL team
# Email: ksl.taskforce@gmail.com
# Description:
# Doppelfind plugin is used to find indications of the Process Doppelganging
# technique. This is done by checking write access permissions of the image file
# and by seeking a relation between the image file object and a transaction object.
# The plugin outputs processes that have at least one ioc found.
#
# Flags:
# There several additional flags tha can be used in the plugin:
#
# -I/--dll - Also checks the process's dll files for the same iocs
#
# -S/--summarize - Outputs a process summarize overview. The option
# can be used with -I. When combined the results may vary as dll check
# is also included, but the output remains on a process overview.
#
# IOCs:
#
# [*] A file object of type: IMAGE_FILE shouldn't have a Write-Access
#
# [*] Some of the file objects have a FileObjectExtension attribute. This attribute contains
# more data regarding the file object. One of the attributes is a pointer to a _TXN_PARAMETER_BLOCK object.
# At that object a pointer to a transaction can be found. A process with a file object
# of type: IMAGE_FILE that is loaded/related to a transaction is considered suspicious.

# Imports
import os
from volatility.plugins.taskmods import PSList
import volatility.plugins.procdump as procdump
import volatility.debug as debug
import volatility.obj as obj

# Constants
READ_ONLY       = 0
IMAGE_FILE_TYPE = 2
SYSTEM_PROCESS  = 4

class doppelfind(procdump.ProcDump):

    def __init__(self, config, *args, **kwargs):

        procdump.ProcDump.__init__(self, config, *args, **kwargs)
        config.remove_option("BASE")
        config.add_option('DLL', short_option='I', default=False,
                          action='store_true', help='Include dll files for doppelganger check')
        config.add_option("SUMMARIZE", short_option="S", default=False,
                          action='store_true', help="Show result in a table per process.\n"
                                                    "If --dll is used, the results\n"
                                                    "may vary, but still present process "
                                                    "summarization")

    def _get_vads_file_object_name(self, vad_object):
        """
        :param vad_object: _MMVAD object
        :return: A string of the mapped file object name
        Try to get the full name of the mapped file to vad.
        """

        try:
            file_name = vad_object.FileObject.FileName.v()
        except AttributeError:
            return ''
        else:
            return file_name

    def _get_transaction_object_pointer(self, file_extension_pointer, proc_addr_space):
        """
        :param file_extension_pointer: A pointer of FILE_OBJECT.FileObjectExtension
        :param proc_addr_space: Process Address Space
        :return: _KTRANSACTION pointer
        Get the pointer to KTRANSACTION after parsing the PARAMETER BLOCK extrancted
        from the FileObjectExtension.
        """

        file_obj_extension = self._parse_file_object_extension(file_extension_pointer,
                                                               2, proc_addr_space)

        parameter_block = obj.Object("_TXN_PARAMETER_BLOCK", file_obj_extension[1].v(),
                                     proc_addr_space)

        return parameter_block.TransactionObject.v()

    def _parse_file_object_extension(self, file_extension_pointer, array_count, addr_space):
        """
        :param file_extension_pointer: FILE_OBJECT.FileObjectExtension Pointer
        :param array_count: Number of indexes to parse
        :param addr_space: Process Address Space
        :return: volatility.obj.Array
        Parse the FileObjectExtension as an array.
        """
        array = obj.Object("Array", targetType="Pointer", offset=file_extension_pointer,
                           count=array_count, vm=addr_space)

        return array

    def get_image_files_for_process(self, task, proc_full_path, include_dll):
        """
        :param task: _EPROCESS structure of the process
        :return: a list of all vad objects for a given process
        Get all the type IMAGE_FILE file objects from a given process.
        """

        proc_image_files = []

        for vad, addr_space in task.get_vads():

            # Check if there is a file object
            file_name = self._get_vads_file_object_name(vad)

            # Skip to the next vad if there is not file object or if the file
            # object isn't an IMAGE FILE
            if file_name and vad.u.VadFlags.VadType.v() == IMAGE_FILE_TYPE:

                # Take only the process's image file - the include dll should be false
                # and the file object's path is part of the process's full path
                if not include_dll and file_name in proc_full_path:
                    return [vad.FileObject]

                proc_image_files.append(vad.FileObject)

        return proc_image_files

    def is_related_to_transaction(self, file_obj, proc_addr_space):
        """
        :param file_obj: FILE_OBJECT
        :param proc_addr_space: Process Address Space
        :return: Boolean
        Check if the File Object has a FileObjectExtension and if there
        is a relation to a transaction.
        """
        # A pointer to the transaction object is part of the file object extension
        if file_obj.FileObjectExtension.v():

            # Parse the file object extension
            file_obj_extension = self._parse_file_object_extension(file_obj.FileObjectExtension.v(),
                                                                   2, proc_addr_space)

            # The pointer to the _TXN_PARAMETER_BLOCK is at the second index
            if file_obj_extension[1].v():
                return True

        return False

    def get_proc_name(self, proc, address_space):
        """
        :param proc: _EPROCESS object
        :param address_space: Process's address space object
        :return: The process's loaded image file name
        Extract the process's loaded image file name from
        the _EPROCESS structure.
        """
        name = address_space.read(proc.SeAuditProcessCreationInfo.ImageFileName.Name.Buffer,
                                  proc.SeAuditProcessCreationInfo.ImageFileName.Name.Length).replace("\x00", '')

        return name if name else ''

    def calculate(self):

        # Get all processes
        ps = PSList(self._config)
        psdata = ps.calculate()

        for proc in psdata:

            # Skip System process
            if proc.UniqueProcessId == SYSTEM_PROCESS:
                continue

            # Set process summarize
            proc_found_write = False
            proc_found_related_trans = False
            file_objects = []

            # Get process's address space
            proc_addr_space = proc.get_process_address_space()

            # Get process's full path
            proc_full_path = self.get_proc_name(proc, proc_addr_space)

            # Get all file objects that are type of an Image File
            self.image_files = self.get_image_files_for_process(proc, proc_full_path,
                                                                self._config.DLL)

            # Check file object's parameters
            for file_obj in self.image_files:

                transaction_object_pointer = 0

                # Set IOC
                iocs = {"Has Write Access": False,
                   "Related to Transaction": False}

                # An image file shouldn't have write access
                if file_obj.WriteAccess != READ_ONLY:
                    iocs["Has Write Access"] = True
                    proc_found_write = True

                # Check if the image file is related to a transaction object
                if self.is_related_to_transaction(file_obj, proc_addr_space):
                    transaction_object_pointer = self._get_transaction_object_pointer(
                        file_obj.FileObjectExtension.v(), proc_addr_space)
                    iocs["Related to Transaction"] = True
                    proc_found_related_trans = True

                # Add findings only if something is found or verbose is enabled
                if True in iocs.values() or self._config.verbose:
                    file_objects.append((file_obj, iocs, transaction_object_pointer))

            # Return found processes only
            if file_objects:
                yield proc, file_objects, proc_found_write, proc_found_related_trans

    def render_text(self, outfd, data):

        dump_dir = self._config.DUMP_DIR

        # Check if given folder is valid
        if dump_dir and not os.path.isdir(dump_dir):
            debug.error("'{}' was not found".format(dump_dir))

        # Configure table header
        if self._config.SUMMARIZE:
            self.table_header(outfd, [('Offset(V)', '[addrpad]'),
                                      ('Name', '<20'),
                                      ('PID', '>6'),
                                      ('PPID', '>6'),
                                      ('Write Access', '5'),
                                      ('Related Transaction', '5')])
        else:
            outfd.write("\nDoppelganger Finder:\n")
            outfd.write("--------------------\n\n")

        # Iterate results to print them out
        for proc, file_objects, proc_found_write, proc_found_related_trans \
                in data:

            proc_pid = proc.UniqueProcessId
            proc_ppid = proc.InheritedFromUniqueProcessId
            proc_name = proc.ImageFileName
            proc_addr_space = proc.get_process_address_space()
            transactions = []

            # Dump process if requested
            if dump_dir:

                file_name = "Process.{0}.Pid.{1}.dmp".format(proc_name, proc_pid)
                full_path = os.path.join(dump_dir, file_name)
                self.dump_pe(proc_addr_space, proc.Peb.ImageBaseAddress, full_path)

            # Print out results in a table format
            if self._config.SUMMARIZE:
                self.table_row(outfd,
                               proc.v(),
                               proc_name,
                               proc_pid,
                               proc_ppid,
                               str(proc_found_write),
                               str(proc_found_related_trans),)

            else:

                # The process headline
                outfd.write("Process: {} PID: {} PPID: {}\n".format(proc_name,
                                                                  proc_pid,
                                                                  proc_ppid))
                outfd.write("Number of Image Files: {}\n\n".format(len(file_objects)))

                # Create a table header
                self.table_header(outfd, [('Offset(V)', '[addrpad]'),
                                      ('Name', '<20'),
                                      ('Path', '<30'),
                                      ('Write Access', '5'),
                                      ('Related Transaction', '5')])

                # Iterate through each the relevant file object
                # of each process and print out basic info with ioc check
                for file_obj, iocs, transaction_obj_pointer in file_objects:

                    full_path = file_obj.FileName.v()
                    name = os.path.basename(full_path)
                    dir_path = os.path.dirname(full_path)

                    # Get transaction data if exits
                    if transaction_obj_pointer:

                        # Parse transaction object
                        transaction_obj = obj.Object("_KTRANSACTION",
                                                     transaction_obj_pointer,
                                                     proc_addr_space)

                        transactions.append((transaction_obj, name))

                    self.table_row(outfd,
                                   file_obj.v(),
                                   name,
                                   dir_path,
                                   str(iocs["Has Write Access"]),
                                   str(iocs["Related to Transaction"]))

                outfd.write("------------------ -------------------- ------------------------------ ------------ -------------------\n\n")

                # Print out transaction information if exists
                if transactions:
                    outfd.write("Found transactions information:\n\n")

                    self.table_header(outfd, [('Transaction(V)', '[addrpad]'),
                                          ('Description', '<15'),
                                          ('File Object Name', '<20'),
                                          ('State', '<25'),
                                          ('Outcome', '<20')])

                    for transaction_obj, file_name in transactions:
                        self.table_row(outfd,
                                       transaction_obj.v(),
                                       str(transaction_obj.Description),
                                       file_name,
                                       str(transaction_obj.State),
                                       str(transaction_obj.Outcome))