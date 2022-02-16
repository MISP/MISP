```mermaid
graph TD;
  create_random_dir-->taxii_push
  taxii_push-->read_filters
  read_filters-->create_chunk_size_envelope
  create_chunk_size_envelope-->chunk_loop
  chunk_loop-->fetchEvent
  fetchEvent-->save_to_random_dir
  save_to_random_dir-->chunk_loop
  chunk_loop-->execute_taxii_script
  execute_taxii_script-->read_random_dir_contents
  read_random_dir_contents-->loop_files
  loop_files-->read_file
  read_file-->convert_to_stix
  convert_to_stix-->push_to_taxii
  push_to_taxii-->loop_files
  push_to_taxii-->remove_random_dir
  ```
