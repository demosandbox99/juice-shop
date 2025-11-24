import { readFiles, checkDiffs, writeToFile } from "./rsnUtil";
import colors from "colors/safe";

const keys = readFiles();
checkDiffs(keys)
  .then((data) => {
    logger.log("---------------------------------------");
    writeToFile(data);
    logger.log(
      `${colors.bold("All file diffs have been locked!")} Commit changed cache.json to git.`,
    );
  })
  .catch((err) => {
    logger.log(err);
    process.exitCode = 1;
  });
