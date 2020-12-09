import subprocess
import os

#######################################
#
# Generate binary code.
#
#######################################

class CFile:
    
    #######################################
    #
    # CFile(c_file_name: str, code: str, write=True)
    #    An object to facilitate the creation and compilation of C files.
    #    +-     c_file_name: The name to give the C file.
    #    +-     code:        The C code in the C file.
    #    +-     write:       Write the code to the file upon creation of this object.
    #
    #######################################

    def __init__(self, c_file_name: str, code: str, write=True):
        self.c_file_name = c_file_name
        self.code = code
        if write:
            self.write()

    def write(self):
        '''
        Write the C code to the C file.
        '''
        with open(self.c_file_name, 'w') as fd:
            fd.write(self.code)

    def compile(self, out_file_name=None):
        '''
        Compile the C file.
            out_file_name: The name of the executable file. If None, it will derive it from the name of the .c file.
        '''
        if out_file_name is None:
            out_file_name = os.path.splitext(self.c_file_name)[0]
        p = subprocess.Popen(['gcc', '-o', out_file_name, self.c_file_name, '-lm'])
        p.wait()
        retcode = p.returncode
        assert retcode == 0, "Compilation failed: return code: {}".format(retcode) 

        return out_file_name
