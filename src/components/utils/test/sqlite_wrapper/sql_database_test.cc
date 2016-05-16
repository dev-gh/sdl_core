/* Copyright (c) 2016, Ford Motor Company
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
*
* Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following
* disclaimer in the documentation and/or other materials provided with the
* distribution.
*
* Neither the name of the Ford Motor Company nor the names of its contributors
* may be used to endorse or promote products derived from this software
* without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

#include "gtest/gtest.h"
#include "sqlite_wrapper/sql_error.h"
#include "sqlite_wrapper/sql_database.h"

using ::utils::dbms::SQLError;
using ::utils::dbms::SQLDatabase;

#ifndef __linux__
#define S_IRUSR 0400
#endif // __linux__

namespace test {
namespace components {
namespace utils {
namespace dbms {

TEST(SQLDatabaseTest, OpenCloseMemory_OpenAndCloseDB_ActsWithoutError) {
  // arrange
  SQLDatabase db("local", "test");
  bool ret = db.Open();

  // assert
  ASSERT_TRUE(ret);

  // act
  db.Close();
}

TEST(SQLDatabaseTest, OpenCloseFile_OpenAndCloseSpecifiedDB_ActsWithoutError) {
  // arrange
  SQLDatabase db("test-database", "test");
  bool ret = db.Open();

  // assert
  ASSERT_TRUE(ret);

  // act
  db.Close();

  remove("test-database.sqlite");
}

TEST(SQLDatabaseTest, OpenDBTwice_NoError) {
  // arrange
  SQLDatabase db("local", "test");
  bool ret = db.Open();

  // assert
  ASSERT_TRUE(ret);

  // act
  ret = db.Open();

  // assert
  ASSERT_TRUE(ret);

  db.Close();
}

TEST(SQLDatabaseTest, CloseDBTwice_NoError) {
  // arrange
  SQLDatabase db("local", "test");
  bool ret = db.Open();

  // assert
  ASSERT_TRUE(ret);

  // act
  db.Close();
  db.Close();
}

TEST(SQLDatabaseTest, Close_DBWasNotOpened_NoError) {
  // act
  SQLDatabase db("local", "test");
  db.Close();
}

TEST(SQLDatabaseTest,
     CommitTransaction_StartAndCommitTransaction_ExpectActsWithoutError) {
  // arrange
  SQLDatabase db("local", "test");

  // assert
  ASSERT_TRUE(db.Open());
  EXPECT_TRUE(db.BeginTransaction());
  EXPECT_TRUE(db.CommitTransaction());

  db.Close();
}

TEST(SQLDatabaseTest,
     RollbackTransaction_StartAndRollbackTransaction_ExpectActsWithoutError) {
  // arrange
  SQLDatabase db("local", "test");

  // assert
  ASSERT_TRUE(db.Open());
  EXPECT_TRUE(db.BeginTransaction());
  EXPECT_TRUE(db.RollbackTransaction());

  db.Close();
}

TEST(SQLDatabaseTest,
     FailedCommitTransaction_CommitTransactionWithoutBeginning_ExpectError) {
  // arrange
  SQLDatabase db("local", "test");

  // assert
  ASSERT_TRUE(db.Open());
  EXPECT_FALSE(db.CommitTransaction());

  db.Close();
}

TEST(
    SQLDatabaseTest,
    FailedRollbackTransaction_RollbackTransactionWithoutBeginning_ExpectError) {
  // arrange
  SQLDatabase db("local", "test");

  // assert
  ASSERT_TRUE(db.Open());
  EXPECT_FALSE(db.RollbackTransaction());

  db.Close();
}

TEST(SQLDatabaseTest, BadTransaction_BeginTransitionWithoutOpenDB_ExpectError) {
  // arrange
  SQLDatabase db("local", "test");

  // assert
  EXPECT_FALSE(db.BeginTransaction());
}

TEST(SQLDatabaseTest, IsReadWrite_FirstOpenDBIsRWSecondIsNot) {
  // arrange
  SQLDatabase db("test-database", "test");

  // assert
  ASSERT_TRUE(db.Open());
  EXPECT_TRUE(db.IsReadWrite());
  db.Close();
  chmod("test-database.sqlite", S_IRUSR);

  // assert
  ASSERT_TRUE(db.Open());
  EXPECT_FALSE(db.IsReadWrite());

  db.Close();
  remove("test-database.sqlite");
}

}  // namespace dbms
}  // namespace utils
}  // namespace components
}  // namespace test
