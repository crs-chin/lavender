#ifndef __TEST_H
#define __TEST_H

#ifdef LOG_INFO
#undef LOG_INFO
#define LOG_INFO(args...)
#endif

#ifdef LOG_WARN
#undef LOG_WARN
#define LOG_WARN(args...)
#endif

#ifdef LOG_ERROR
#undef LOG_ERROR
#define LOG_ERROR(args...)
#endif

#ifdef LOG_EMERG
#undef LOG_EMERG
#define LOG_EMERG(args...)
#endif

#endif  /* ! __TEST_H */
