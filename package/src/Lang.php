<?php

namespace laf;

class Lang
{
    const GLOBAL_ERROR = "laf error\n";
    const GLOBAL_CHECK_CONFIG = "Check your configuration file :\n";

    const UNABLE_TO_PARSER_YAML =
        Lang::GLOBAL_ERROR.
        Lang::GLOBAL_CHECK_CONFIG.
        "Unable to parse the YAML file configuration";
}
